import os
import time
import csv
import base64
import re
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Configuration
ENV = os.getenv("KALSHI_ENV", "demo").lower().strip()

BASE_URL = (
    "https://demo-api.kalshi.co/trade-api/v2"
    if ENV == "demo"
    else "https://api.elections.kalshi.com/trade-api/v2"
)

# --- AUTH / KEY LOADING (robust: supports PATH or inline PEM) ---

API_KEY_ID = (os.getenv("KALSHI_API_KEY_ID") or os.getenv("KALSHI_API_KEY") or "").strip()

PRIVATE_KEY_PATH = (os.getenv("KALSHI_PRIVATE_KEY_PATH") or "").strip()
PRIVATE_KEY_ENV = (os.getenv("KALSHI_PRIVATE_KEY") or "").strip()

def _resolve_path(p: str) -> str:
    if not p:
        return ""
    if not os.path.isabs(p):
        p = os.path.join(SCRIPT_DIR, p)
    return p

PRIVATE_KEY_PEM_BYTES = b""

if PRIVATE_KEY_PATH:
    pk_path = _resolve_path(PRIVATE_KEY_PATH)
    try:
        with open(pk_path, "rb") as f:
            PRIVATE_KEY_PEM_BYTES = f.read()
    except FileNotFoundError:
        print(f"⚠️  Private key file not found: {pk_path}")
        PRIVATE_KEY_PEM_BYTES = b""

elif PRIVATE_KEY_ENV:
    maybe_path = _resolve_path(PRIVATE_KEY_ENV)
    if os.path.exists(maybe_path) and os.path.isfile(maybe_path):
        try:
            with open(maybe_path, "rb") as f:
                PRIVATE_KEY_PEM_BYTES = f.read()
        except FileNotFoundError:
            print(f"⚠️  Private key file not found: {maybe_path}")
            PRIVATE_KEY_PEM_BYTES = b""
    else:
        PRIVATE_KEY_PEM_BYTES = PRIVATE_KEY_ENV.replace("\\n", "\n").encode("utf-8")

PRIVATE_KEY_OBJ = None
if API_KEY_ID and PRIVATE_KEY_PEM_BYTES:
    try:
        PRIVATE_KEY_OBJ = serialization.load_pem_private_key(PRIVATE_KEY_PEM_BYTES, password=None)
    except Exception:
        PRIVATE_KEY_OBJ = None

# Screening criteria
MAX_DAYS = 60
MIN_DAYS = 0
PROB_THRESHOLD_CENTS = 80
# Upper bound is exclusive in filter logic; 98 means include 97c.
MAX_PROB_THRESHOLD_CENTS = 98
MIN_LIQUIDITY = 50
MIN_OPEN_INTEREST = 50
MIN_TOTAL_VOLUME = 50
MIN_VOL_24H = 1
EXCLUDE_MVE = True
QUERY_API_STATUSES = ("open", "paused")
TARGET_MARKET_STATUSES = {"active", "open", "paused"}

# =============== QUALITY FILTERING - IDENTIFIES ACTUALLY PREDICTABLE BETS ===============

ENABLE_QUALITY_FILTER = True
MIN_QUALITY_SCORE = 40  # 0-100 scale, bets below this are filtered out

# Keywords that signal UNPREDICTABLE bets (avoid these)
AVOID_KEYWORDS = [
    "exact", "exactly", "between", "range",
    "temperature", "high temp", "low temp", "temp",
    "precipitation", "rain", "snow", "wind", "weather",
    "decimal", "hundredth", "tenth",
    "degree", "degrees"
]

# Keywords that signal PREDICTABLE bets (prefer these)  
PREFER_KEYWORDS = [
    "total", "over", "under", "at least", "more than", "less than",
    "win", "lose", "pass", "fail", "confirmed", "appointed",
    "album", "sales", "box office", "revenue", "views", "streams",
    "election", "vote", "majority", "champion", "winner",
    "above", "below", "greater", "fewer"
]

# Series patterns that are typically low quality (fine-grained predictions)
AVOID_SERIES_PATTERNS = [
    r"TEMP-",          # Temperature markets
    r"PREC-",          # Precipitation  
    r"WIND-",          # Wind speed
    r".*-\d+TO\d+$",   # Range buckets like "32TO33" or "100TO105"
    r".*-B\d+\.\d+",   # Decimal precision markets
    r".*-T\d+\.\d+",   # Time precision markets
]

def calculate_quality_score(market: dict) -> tuple[float, list[str]]:
    """
    Calculate how predictable a bet actually is (0-100 scale).
    
    Returns: (score, reasons list)
    
    Higher score = more predictable/better bet
    
    Factors:
    - Title keywords (avoid weather, exact numbers; prefer totals, thresholds)
    - Series patterns (avoid fine-grained buckets)
    - Market probability (very high might actually be safer)
    - Time to resolution (sooner = less uncertainty)
    """
    score = 50.0  # baseline
    reasons = []
    
    title = market.get("title", "").lower()
    ticker = market.get("ticker", "").upper()
    
    # Heavy penalty for avoid keywords (these are usually coin flips)
    avoid_matches = [kw for kw in AVOID_KEYWORDS if kw in title]
    if avoid_matches:
        penalty = len(avoid_matches) * 15
        score -= penalty
        reasons.append(f"Avoid keywords: {', '.join(avoid_matches[:3])}")
    
    # Bonus for prefer keywords (objective, measurable outcomes)
    prefer_matches = [kw for kw in PREFER_KEYWORDS if kw in title]
    if prefer_matches:
        bonus = min(len(prefer_matches) * 10, 20)  # cap at +20
        score += bonus
        reasons.append(f"Predictable type: {', '.join(prefer_matches[:2])}")
            
    # Check series patterns (fine-grained buckets are bad)
    for pattern in AVOID_SERIES_PATTERNS:
        if re.match(pattern, ticker):
            score -= 25
            reasons.append(f"Fine-grained series pattern")
            break
            
    # Very high probability markets (95%+) might be genuinely safe
    prob = market.get("best_ask_cents", 90)
    if prob >= 95:
        score += 8
        reasons.append(f"Very high market confidence ({prob}%)")
    elif prob <= 91:
        # Lower end of range, more uncertainty
        score -= 3
        
    # Sooner resolution = less uncertainty
    days = market.get("days_until_close", 30)
    if days <= 3:
        score += 12
        reasons.append("Resolves very soon")
    elif days <= 7:
        score += 8
        reasons.append("Resolves within a week")
    elif days <= 14:
        score += 4
    elif days >= 25:
        score -= 5
        reasons.append("Long time until resolution")
        
    # High liquidity suggests market is well-informed
    liq = market.get("liquidity", 0)
    if liq >= 5000:
        score += 5
        reasons.append("High liquidity market")
    elif liq >= 2000:
        score += 2
        
    # Detect if this is part of a large bucket set (many similar markets)
    # This is hard to detect perfectly, but we can look for patterns
    if re.search(r'-[A-Z]?\d+$', ticker):  # ends with a number (likely bucket)
        score -= 8
        reasons.append("Likely part of bucket set")
    
    final_score = max(0, min(100, score))
    return final_score, reasons


def iso_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _sign_rsa_pss_b64(private_key, message: bytes) -> str:
    sig_bytes = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig_bytes).decode("utf-8")


def get_kalshi_headers(method: str, path: str):
    headers = {"Content-Type": "application/json"}

    if ENV != "prod" or not API_KEY_ID or not PRIVATE_KEY_OBJ:
        return headers

    timestamp = str(int(time.time() * 1000))
    path_no_query = path.split("?")[0]
    msg = f"{timestamp}{method.upper()}{path_no_query}".encode("utf-8")

    signature_b64 = _sign_rsa_pss_b64(PRIVATE_KEY_OBJ, msg)

    headers["KALSHI-ACCESS-KEY"] = API_KEY_ID
    headers["KALSHI-ACCESS-SIGNATURE"] = signature_b64
    headers["KALSHI-ACCESS-TIMESTAMP"] = timestamp
    return headers


def fetch_markets(status: str | None = None):
    cursor = None
    out = []
    seen_tickers = set()

    while True:
        params = {"limit": 1000}
        if EXCLUDE_MVE:
            params["mve_filter"] = "exclude"
        if status:
            params["status"] = status
        if cursor:
            params["cursor"] = cursor

        try:
            path = "/trade-api/v2/markets"
            headers = get_kalshi_headers("GET", path)

            r = requests.get(f"{BASE_URL}/markets", params=params, headers=headers, timeout=30)
            r.raise_for_status()
            data = r.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching markets: {e}")
            break

        for m in data.get("markets", []):
            ticker = (m.get("ticker") or "").strip()
            if ticker and ticker in seen_tickers:
                continue
            if ticker:
                seen_tickers.add(ticker)
            out.append(m)
        cursor = data.get("cursor")
        if not cursor:
            break

    return out


_event_cache = {}

def slugify(text: str) -> str:
    if not text:
        return ""
    s = text.strip().lower()
    s = s.replace("&", " and ")
    s = s.replace("'", "")
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s

def fetch_event(event_ticker: str) -> dict | None:
    et = (event_ticker or "").strip()
    if not et:
        return None

    path = f"/trade-api/v2/events/{et}"
    headers = get_kalshi_headers("GET", path)

    r = requests.get(f"{BASE_URL}/events/{et}", headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    return data.get("event")

def get_event_url(event_ticker: str) -> str:
    et = (event_ticker or "").strip()
    if not et:
        return ""

    et_l = et.lower()
    if et_l in _event_cache:
        return _event_cache[et_l]

    fallback = f"https://kalshi.com/markets/{et_l}"

    try:
        ev = fetch_event(et)
        if not ev:
            _event_cache[et_l] = fallback
            return fallback

        series = (ev.get("series_ticker") or "").strip() or et.split("-", 1)[0]
        series_l = series.lower()

        slug_source = (ev.get("sub_title") or ev.get("title") or series).strip()
        slug = slugify(slug_source) or series_l

        url = f"https://kalshi.com/markets/{series_l}/{slug}/{et_l}"
        _event_cache[et_l] = url
        return url

    except Exception:
        _event_cache[et_l] = fallback
        return fallback


def screen(markets, return_stats: bool = False):
    now = datetime.now(timezone.utc)
    earliest_close = now + timedelta(days=MIN_DAYS)
    latest_close = now + timedelta(days=MAX_DAYS)
    filter_stats = {
        "total": 0,
        "status_filtered": 0,
        "is_provisional": 0,
        "mve_collection_ticker": 0,
        "book_locked_0_or_100": 0,
        "missing_close_time": 0,
        "bad_close_time": 0,
        "outside_time_window": 0,
        "missing_pricing": 0,
        "invalid_asks": 0,
        "probability_band": 0,
        "activity_filter": 0,
        "quality_filter": 0,
        "passed": 0,
    }

    hits = []
    for m in markets:
        filter_stats["total"] += 1
        status = (m.get("status") or "").strip().lower()
        if TARGET_MARKET_STATUSES and status not in TARGET_MARKET_STATUSES:
            filter_stats["status_filtered"] += 1
            continue

        # Filter out provisional markets (new markets with no trading activity)
        if m.get("is_provisional"):
            filter_stats["is_provisional"] += 1
            continue
            
        # Filter out MVE markets (despite API filter, some still get through)
        if m.get("mve_collection_ticker"):
            filter_stats["mve_collection_ticker"] += 1
            continue
        
        # Filter out markets with no real pricing (0 or 100 only)
        yes_ask_raw = m.get("yes_ask")
        no_ask_raw = m.get("no_ask")
        if (yes_ask_raw == 0 or yes_ask_raw == 100) and (no_ask_raw == 0 or no_ask_raw == 100):
            filter_stats["book_locked_0_or_100"] += 1
            continue
        
        close_time = m.get("close_time")
        if not close_time:
            filter_stats["missing_close_time"] += 1
            continue

        try:
            close_dt = iso_to_dt(close_time)
        except Exception:
            filter_stats["bad_close_time"] += 1
            continue

        if not (earliest_close <= close_dt <= latest_close):
            filter_stats["outside_time_window"] += 1
            continue

        yes_ask = m.get("yes_ask")
        no_ask = m.get("no_ask")
        yes_bid = m.get("yes_bid")
        no_bid = m.get("no_bid")

        def to_int(x):
            if x is None:
                return None
            try:
                return int(round(float(x)))
            except (ValueError, TypeError):
                return None

        yes_ask = to_int(yes_ask)
        no_ask = to_int(no_ask)
        yes_bid = to_int(yes_bid)
        no_bid = to_int(no_bid)

        if yes_ask is None and no_bid is not None:
            yes_ask = 100 - no_bid
        if no_ask is None and yes_bid is not None:
            no_ask = 100 - yes_bid

        if yes_ask is None and no_ask is None:
            filter_stats["missing_pricing"] += 1
            continue

        best_side = None
        best_ask = -1
        opposite_ask = -1

        if yes_ask is not None and yes_ask > best_ask:
            best_side, best_ask = "YES", yes_ask
            opposite_ask = no_ask if no_ask is not None else (100 - yes_ask)
        if no_ask is not None and no_ask > best_ask:
            best_side, best_ask = "NO", no_ask
            opposite_ask = yes_ask if yes_ask is not None else (100 - no_ask)

        if best_ask >= 100 or (opposite_ask is not None and opposite_ask <= 0):
            filter_stats["invalid_asks"] += 1
            continue
        if opposite_ask is None:
            filter_stats["invalid_asks"] += 1
            continue

        if best_ask < PROB_THRESHOLD_CENTS or best_ask >= MAX_PROB_THRESHOLD_CENTS:
            filter_stats["probability_band"] += 1
            continue

        liquidity = int(m.get("liquidity") or 0)
        open_interest = int(m.get("open_interest") or 0)
        total_volume = int(m.get("volume") or 0)
        vol_24h = int(m.get("volume_24h") or 0)
        has_depth = (
            liquidity >= MIN_LIQUIDITY
            or open_interest >= MIN_OPEN_INTEREST
            or total_volume >= MIN_TOTAL_VOLUME
        )
        if not has_depth or vol_24h < MIN_VOL_24H:
            filter_stats["activity_filter"] += 1
            continue

        days_until = (close_dt - now).days

        market_ticker = (m.get("ticker") or "").strip()
        event_ticker = (m.get("event_ticker") or "").strip()

        if not event_ticker:
            event_ticker = market_ticker.rsplit("-", 1)[0] if market_ticker.count("-") >= 2 else market_ticker

        # Calculate quality score
        market_data = {
            "title": m.get("title", ""),
            "ticker": market_ticker,
            "best_ask_cents": best_ask,
            "days_until_close": days_until,
            "liquidity": liquidity,
        }
        quality_score, quality_reasons = calculate_quality_score(market_data)
        
        # Filter by quality if enabled
        if ENABLE_QUALITY_FILTER and quality_score < MIN_QUALITY_SCORE:
            filter_stats["quality_filter"] += 1
            continue

        hits.append({
            "ticker": market_ticker,
            "event_ticker": event_ticker,
            "title": m.get("title", ""),
            "status": m.get("status", ""),
            "best_side": best_side,
            "best_ask_cents": best_ask,
            "yes_ask": yes_ask,
            "no_ask": no_ask,
            "liquidity": liquidity,
            "open_interest": open_interest,
            "volume": total_volume,
            "volume_24h": vol_24h,
            "close_time": close_time,
            "close_dt": close_dt,
            "days_until_close": days_until,
            "quality_score": quality_score,
            "quality_reasons": "; ".join(quality_reasons) if quality_reasons else "Standard",
            # Use the full market ticker (not event ticker) and preserve case.
            "url": f"https://kalshi.com/markets/{market_ticker}" if market_ticker else "",
        })
        filter_stats["passed"] += 1

    # Sort by quality score first, then probability
    hits.sort(key=lambda x: (-x["quality_score"], -x["best_ask_cents"], x["close_dt"]))
    if return_stats:
        return hits, filter_stats
    return hits


if __name__ == "__main__":
    print("🎯 Kalshi High-Probability Bet Screener with Quality Filter")
    print(f"Environment: {ENV}")
    print(f"API: {BASE_URL}")

    if ENV == "prod":
        if not API_KEY_ID or not PRIVATE_KEY_OBJ:
            print("\n⚠️  ERROR: Missing/invalid API credentials!")
            print("   Need KALSHI_API_KEY_ID (or KALSHI_API_KEY) AND either:")
            print("   - KALSHI_PRIVATE_KEY_PATH pointing to a PEM file, OR")
            print("   - KALSHI_PRIVATE_KEY as ONE LINE with \\n newlines in .env (or a .pem path)")
            exit(1)

    print(f"Filtering for: {PROB_THRESHOLD_CENTS}-{MAX_PROB_THRESHOLD_CENTS-1}% probability")
    print(f"Time window: {MIN_DAYS}-{MAX_DAYS} days from now")
    print(
        "Minimum activity: "
        f"liquidity>={MIN_LIQUIDITY} OR open_interest>={MIN_OPEN_INTEREST} OR volume>={MIN_TOTAL_VOLUME}; "
        f"and volume_24h>={MIN_VOL_24H}"
    )
    print(f"Quality filter: {'ENABLED' if ENABLE_QUALITY_FILTER else 'DISABLED'} (min score: {MIN_QUALITY_SCORE}/100)\n")

    print("Fetching markets...")
    markets = []
    for s in QUERY_API_STATUSES:
        fetched = fetch_markets(s)
        print(f"  - {s}: {len(fetched)} markets")
        markets.extend(fetched)

    # Safety dedupe in case API ignores status parameter in some environments.
    deduped = {}
    for m in markets:
        ticker = (m.get("ticker") or "").strip()
        if ticker:
            deduped[ticker] = m
    markets = list(deduped.values())

    print(f"Retrieved {len(markets)} unique markets from API statuses: {', '.join(QUERY_API_STATUSES)}")
    print(f"Local status allowlist: {', '.join(sorted(TARGET_MARKET_STATUSES))}")

    hits, filter_stats = screen(markets, return_stats=True)

    print(f"\n✅ Found {len(hits)} HIGH-QUALITY markets meeting criteria.\n")

    print("Filter drop-off summary:")
    for k, v in filter_stats.items():
        if k in ("total", "passed"):
            continue
        print(f"  - {k}: {v}")
    print(f"  - passed: {filter_stats['passed']} / {filter_stats['total']}\n")

    csv_filename = f"kalshi_quality_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "quality_score", "ticker", "event_ticker", "url", "status",
            "probability", "side", "days_until",
            "liquidity", "open_interest", "volume", "volume_24h", "close_time", "title", "quality_reasons"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for h in hits:
            writer.writerow({
                "quality_score": f"{h['quality_score']:.1f}",
                "ticker": h["ticker"],
                "event_ticker": h["event_ticker"],
                "url": h["url"],
                "status": h["status"],
                "probability": f"{h['best_ask_cents']}%",
                "side": h["best_side"],
                "days_until": h["days_until_close"],
                "liquidity": h["liquidity"],
                "open_interest": h["open_interest"],
                "volume": h["volume"],
                "volume_24h": h["volume_24h"],
                "close_time": h["close_time"],
                "title": h["title"],
                "quality_reasons": h["quality_reasons"],
            })

    print(f"📊 Results saved to: {csv_filename}\n")
    
    # Show top 10 in terminal
    if hits:
        print("🏆 Top 10 Highest-Quality Bets:\n")
        print(f"{'QUAL':<5} {'PROB':<5} {'DAYS':<5} {'TICKER':<25} TITLE")
        print("=" * 100)
        for h in hits[:10]:
            title_short = h["title"][:50] if len(h["title"]) > 50 else h["title"]
            print(f'{h["quality_score"]:>4.0f}  {h["best_ask_cents"]:>3}%  {h["days_until_close"]:>3}d  {h["ticker"]:<25} {title_short}')
        
        if len(hits) > 10:
            print(f"\n... and {len(hits) - 10} more (see CSV for full list)")
    
    print(f"\n💡 Quality Score Factors:")
    print(f"   ✅ Prefer: objective outcomes (totals, over/under, election results)")
    print(f"   ❌ Avoid: weather, exact numbers, fine-grained buckets")
    print(f"   📈 Bonus: high liquidity, soon resolution, very high probability")
    print(f"\n   Adjust MIN_QUALITY_SCORE (currently {MIN_QUALITY_SCORE}) to be more/less strict")

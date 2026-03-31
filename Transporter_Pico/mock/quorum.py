from mock.constants import W_PRICE, W_REP, W_STAKE, QUORUM_SIZE
from mock.flow import _query_flow_stake_reputation


def _select_quorum(bids: dict) -> dict:
    if not bids:
        return {}

    print(f"[Quorum] Scoring {len(bids)} bidder(s)...")
    scored = []
    for pub_hex, bid in bids.items():
        stake, rep = _query_flow_stake_reputation(pub_hex)
        price = bid["price"]
        if price <= 0.0:
            print(f"[Quorum]   {pub_hex[:12]}... price={price} — skipping (invalid price)")
            continue
        score = W_PRICE * (1.0 / price) + W_REP * rep + W_STAKE * stake
        scored.append({
            "pubkey_hex": pub_hex,
            "ip":         bid["ip"],
            "price":      price,
            "stake":      stake,
            "reputation": rep,
            "score":      score,
        })
        print(f"[Quorum]   {pub_hex[:12]}...  price={price:.4f}  stake={stake:.2f}  "
              f"rep={rep:.4f}  score={score:.4f}")

    scored.sort(key=lambda x: x["score"], reverse=True)
    top = scored[:QUORUM_SIZE]
    return {e["pubkey_hex"]: e["ip"] for e in top}
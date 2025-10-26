import pandas as pd
import os

# Convert packet-level CSV to flow-level CSV for ML processing.
INPUT_CSV = "datasets/packets_raw.csv"
OUTPUT_CSV = "datasets/sample_traffic.csv"

# Build flow-level features from packet-level data.
def build_flows(df):
    for col in ['tcp.srcport','tcp.dstport','udp.srcport','udp.dstport','_ws.col.protocol','frame.len']:
        if col not in df.columns:
            df[col] = 0

    df['sport'] = df.apply(lambda r: int(r['tcp.srcport']) if r['tcp.srcport'] != 0 else int(r['udp.srcport']), axis=1)
    df['dport'] = df.apply(lambda r: int(r['tcp.dstport']) if r['tcp.dstport'] != 0 else int(r['udp.dstport']), axis=1)
    df['_ws.col.protocol'] = df['_ws.col.protocol'].fillna('OTHER')

    df['flow_key'] = df.apply(lambda r: f"{r['ip.src']}_{r['ip.dst']}_{r['sport']}_{r['dport']}_{r['_ws.col.protocol']}", axis=1)

    flows = []
    for key, g in df.groupby('flow_key'):
        start = g['frame.time_epoch'].min()
        end = g['frame.time_epoch'].max()
        duration = end - start if end>start else 0.0
        total_pkts = len(g)
        total_bytes = g['frame.len'].sum()
        mean_pkt_len = g['frame.len'].mean()
        pkt_rate = total_pkts/duration if duration>0 else total_pkts
        protocol = g['_ws.col.protocol'].iloc[0]

        flows.append({
            'flow_key': key,
            'duration': duration,
            'total_pkts': total_pkts,
            'total_bytes': total_bytes,
            'mean_pkt_len': mean_pkt_len,
            'pkt_rate': pkt_rate,
            'protocol': protocol,
            'label': 0 
        })

    return pd.DataFrame(flows)

# Main execution
def main():
    if not os.path.exists(INPUT_CSV):
        print(f"Input CSV missing: {INPUT_CSV}")
        return

    df = pd.read_csv(INPUT_CSV)
    print("Loaded packets:", df.shape)
    df_flows = build_flows(df)
    df_flows.to_csv(OUTPUT_CSV, index=False)
    print("Saved flow-level CSV:", OUTPUT_CSV)

if __name__ == "__main__":
    main()

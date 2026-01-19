import pandas as pd
import sys
import os


def collect_samples():
    """Read flows from logs/malicious_flows.csv and prepare them as normal samples"""
    
    flow_file = "../logs/malicious_flows.csv"
    if not os.path.exists(flow_file):
        print(f"❌ File not found: {flow_file}")
        print("Please run the detector in live mode first to capture some background traffic.")
        return
    
    df = pd.read_csv(flow_file, header=None, 
                     names=['duration', 'total_pkts', 'total_bytes', 'mean_pkt_len', 'pkt_rate', 'protocol'])
    
    df['duration'] = pd.to_numeric(df['duration'], errors='coerce')
    df['total_pkts'] = pd.to_numeric(df['total_pkts'], errors='coerce')
    df['total_bytes'] = pd.to_numeric(df['total_bytes'], errors='coerce')
    df['mean_pkt_len'] = pd.to_numeric(df['mean_pkt_len'], errors='coerce')
    df['pkt_rate'] = pd.to_numeric(df['pkt_rate'], errors='coerce')
    df['protocol'] = pd.to_numeric(df['protocol'], errors='coerce')
    
    df = df.dropna()
    
    print(f"✓ Loaded {len(df)} captured flows")
    
    normal_df = df[(df['pkt_rate'] < 100) & (df['total_pkts'] < 500)].copy()
    
    print(f"✓ Filtered to {len(normal_df)} normal-looking flows")
    
    if len(normal_df) == 0:
        print("⚠️  No normal traffic found. Try capturing for longer without running simulator.")
        return
    
    normal_df['flow_key'] = ['windows_normal_' + str(i) for i in range(len(normal_df))]
    normal_df['label'] = 0
    
    protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP'}
    normal_df['protocol'] = normal_df['protocol'].map(lambda x: protocol_map.get(int(x), 'OTHER'))
    
    normal_df = normal_df[['flow_key', 'duration', 'total_pkts', 'total_bytes', 'mean_pkt_len', 'pkt_rate', 'protocol', 'label']]
    
    output_file = "../datasets/windows_normal_traffic.csv"
    normal_df.to_csv(output_file, index=False)
    print(f"✓ Saved {len(normal_df)} normal samples to: {output_file}")
    print("\nSample rows:")
    print(normal_df.head(10))
    print("\nNext steps:")
    print("1. Run: python merge_training_data.py")
    print("2. Run: python train_model.py")

if __name__ == "__main__":
    collect_samples()

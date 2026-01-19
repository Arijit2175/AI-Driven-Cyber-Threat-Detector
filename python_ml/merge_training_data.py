import pandas as pd
import os

def merge_datasets():
    """Merge original sample_traffic.csv with captured Windows normal traffic"""
    
    original_file = "../datasets/sample_traffic.csv"
    windows_file = "../datasets/windows_normal_traffic.csv"
    output_file = "../datasets/sample_traffic.csv"
    backup_file = "../datasets/sample_traffic_original.csv"
    
    if not os.path.exists(windows_file):
        print(f"❌ Windows traffic file not found: {windows_file}")
        print("Run collect_normal_samples.py first!")
        return
    
    if not os.path.exists(backup_file):
        df_original = pd.read_csv(original_file)
        df_original.to_csv(backup_file, index=False)
        print(f"✓ Backed up original dataset to: {backup_file}")
    
    df_original = pd.read_csv(original_file)
    df_windows = pd.read_csv(windows_file)
    
    print(f"Original dataset: {len(df_original)} flows")
    print(f"Windows traffic: {len(df_windows)} flows")
    
    df_merged = pd.concat([df_original, df_windows], ignore_index=True)
    
    print(f"\nMerged dataset: {len(df_merged)} flows")
    print(f"  Normal (label=0): {(df_merged['label']==0).sum()}")
    print(f"  Malicious (label=1): {(df_merged['label']==1).sum()}")
    
    df_merged.to_csv(output_file, index=False)
    print(f"\n✓ Saved merged dataset to: {output_file}")
    print("\nNext step: Run python train_model.py to retrain the model")

if __name__ == "__main__":
    merge_datasets()

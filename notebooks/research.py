import subprocess
import pandas as pd
from io import StringIO
import os
import shutil

def pcap_to_csv_tshark(pcap_file, output_csv):
    """Simple PCAP to CSV converter using tshark"""
    
    # Check if tshark is installed
    if not shutil.which('tshark'):
        print("ERROR: tshark not found!")
        print("Install Wireshark from: https://www.wireshark.org/download.html")
        print("Make sure 'TShark' component is checked during installation")
        return None
    
    # Run tshark command
    result = subprocess.run([
        'tshark',
        '-r', pcap_file,
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'frame.len',
        '-e', '_ws.col.protocol',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-E', 'header=y',
        '-E', 'separator=,',
        '-E', 'occurrence=f'
    ], capture_output=True, text=True, encoding='utf-8')
    
    # Check for errors
    if result.returncode != 0:
        print(f"tshark error: {result.stderr}")
        return None
    
    # Parse tshark output into DataFrame
    df = pd.read_csv(StringIO(result.stdout))

    print(df.columns.tolist())
    
    # Combine TCP and UDP ports
    df['src_port'] = df['tcp.srcport'].combine_first(df['udp.srcport'])
    df['dst_port'] = df['tcp.dstport'].combine_first(df['udp.dstport'])
    
    # Rename columns
    df = df.rename(columns={
        'frame.time_epoch': 'timestamp',
        'frame.len': 'length',
        '_ws.col.protocol': 'protocol',
        'ip.src': 'src_ip',
        'ip.dst': 'dst_ip'
    })
    
    # Select columns
    df = df[['timestamp', 'length', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port']]
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    
    return df


# Usage
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(script_dir, 'eth2dump-clean-0,5h_1.pcap')
    output_path = os.path.join(script_dir, 'output.csv')
    
    df = pcap_to_csv_tshark(pcap_path, output_path)
    
    if df is not None:
        print(f"✓ Extracted {len(df)} packets")
        print(f"✓ Saved to: {output_path}")
        print(f"\nFirst 5 rows:")
        print(df.head())
        print(f"\nDataFrame info:")
        print(df.info())

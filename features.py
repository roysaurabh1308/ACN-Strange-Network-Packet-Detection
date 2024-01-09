DATA_FILE_PATH = 'data/sample100.csv'
S = pd.read_csv(DATA_FILE_PATH, index_col=0)#, usecols= NUM_COLS)

numCols = list(S.select_dtypes(['float', 'int']).columns)

toRemove = ['Protocol', 'SYN.Flag.Count', 'RST.Flag.Count', 'PSH.Flag.Count', 'ACK.Flag.Count','URG.Flag.Count', 'CWE.Flag.Count', 'ECE.Flag.Count', 'Fwd.Header.Length.1', 'Fwd.Avg.Bytes.Bulk', 'Fwd.Avg.Packets.Bulk',
       'Fwd.Avg.Bulk.Rate', 'Bwd.Avg.Bytes.Bulk', 'Bwd.Avg.Packets.Bulk',
       'Bwd.Avg.Bulk.Rate']
# rare data are those which I think we can't easily from capturing data even by ourseleves
rare= ['Subflow.Fwd.Packets', 'Subflow.Fwd.Bytes','Subflow.Bwd.Packets', 'Subflow.Bwd.Bytes', 'Init_Win_bytes_forward','Init_Win_bytes_backward', 'L7Protocol']
booleans = ['Fwd.PSH.Flags','Bwd.PSH.Flags', 'Fwd.URG.Flags', 'Bwd.URG.Flags']

for col in toRemove:
    numCols.remove(col)
for col in rare:
    numCols.remove(col)
for col in booleans:
    numCols.remove(col)
print(len(numCols))

features = ['Source.Port',
 'Destination.Port',
 'Flow.Duration',
 'Total.Fwd.Packets',
 'Total.Backward.Packets',
 'Total.Length.of.Fwd.Packets',
 'Total.Length.of.Bwd.Packets',
 'Fwd.Packet.Length.Max',
 'Fwd.Packet.Length.Min',
 'Fwd.Packet.Length.Mean',
 'Fwd.Packet.Length.Std',
 'Bwd.Packet.Length.Max',
 'Bwd.Packet.Length.Min',
 'Bwd.Packet.Length.Mean',
 'Bwd.Packet.Length.Std',
 'Flow.Bytes.s',
 'Flow.Packets.s',
 'Flow.IAT.Mean',
 'Flow.IAT.Std',
 'Flow.IAT.Max',
 'Flow.IAT.Min',
 'Fwd.IAT.Total',
 'Fwd.IAT.Mean',
 'Fwd.IAT.Std',
 'Fwd.IAT.Max',
 'Fwd.IAT.Min',
 'Bwd.IAT.Total',
 'Bwd.IAT.Mean',
 'Bwd.IAT.Std',
 'Bwd.IAT.Max',
 'Bwd.IAT.Min',
 'Fwd.Header.Length',
 'Bwd.Header.Length',
 'Fwd.Packets.s',
 'Bwd.Packets.s',
 'Min.Packet.Length',
 'Max.Packet.Length',
 'Packet.Length.Mean',
 'Packet.Length.Std',
 'Packet.Length.Variance',
 'FIN.Flag.Count',
 'Down.Up.Ratio',
 'Average.Packet.Size',
 'Avg.Fwd.Segment.Size',
 'Avg.Bwd.Segment.Size',
 'act_data_pkt_fwd',
 'min_seg_size_forward',
 'Active.Mean',
 'Active.Std',
 'Active.Max',
 'Active.Min',
 'Idle.Mean',
 'Idle.Std',
 'Idle.Max',
 'Idle.Min']
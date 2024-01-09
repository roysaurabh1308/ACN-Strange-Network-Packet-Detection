import os
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
import math

#Constants
DATA_FILE_PATH = 'data/sample100.csv'
INT_MAX = 1000000000
K_FOR_KMEANS = 5
IMP_FEATURES = ['ProtocolName', 'Source.Port','Destination.Port','Flow.Duration','Total.Fwd.Packets','Total.Backward.Packets','Total.Length.of.Fwd.Packets','Total.Length.of.Bwd.Packets','Fwd.Packet.Length.Max','Fwd.Packet.Length.Min','Fwd.Packet.Length.Mean','Fwd.Packet.Length.Std','Bwd.Packet.Length.Max','Bwd.Packet.Length.Min','Bwd.Packet.Length.Mean','Bwd.Packet.Length.Std','Flow.Bytes.s','Flow.Packets.s','Flow.IAT.Mean','Flow.IAT.Std','Flow.IAT.Max','Flow.IAT.Min','Fwd.IAT.Total','Fwd.IAT.Mean','Fwd.IAT.Std','Fwd.IAT.Max','Fwd.IAT.Min','Bwd.IAT.Total','Bwd.IAT.Mean','Bwd.IAT.Std','Bwd.IAT.Max','Bwd.IAT.Min','Fwd.Header.Length','Bwd.Header.Length','Fwd.Packets.s','Bwd.Packets.s','Min.Packet.Length','Max.Packet.Length','Packet.Length.Mean','Packet.Length.Std','Packet.Length.Variance','FIN.Flag.Count','Down.Up.Ratio','Average.Packet.Size','Avg.Fwd.Segment.Size','Avg.Bwd.Segment.Size','act_data_pkt_fwd','min_seg_size_forward','Active.Mean','Active.Std','Active.Max','Active.Min','Idle.Mean','Idle.Std','Idle.Max','Idle.Min']

#Data loading
S = pd.read_csv(DATA_FILE_PATH, usecols=IMP_FEATURES)
# APPS = ["GOOGLE", "YOUTUBE", "..."]
# FEATURES = ["duration", "src_addr", "dest_addr", "..."]
APPS = list(S.ProtocolName.unique())
F = list(S.columns)
F.remove('ProtocolName')
# print(F)
# print(len(F))
# F = ["Total.Length.of.Fwd.Packets", "Total.Length.of.Bwd.Packets"]
# F = list(S.select_dtypes(['float', 'int']).columns)
M = len(F)
N = len(APPS)
T = S.shape[0]
L = S.ProtocolName
FSS = []

'''
['Unnamed: 0', 'Source.Port', 'Destination.Port', 'Protocol', 'Flow.Duration', 'Total.Fwd.Packets', 'Total.Backward.Packets', 'Total.Length.of.Fwd.Packets', 'Total.Length.of.Bwd.Packets', 'Fwd.Packet.Length.Max', 'Fwd.Packet.Length.Min', 'Fwd.Packet.Length.Mean', 'Fwd.Packet.Length.Std', 'Bwd.Packet.Length.Max', 'Bwd.Packet.Length.Min', 'Bwd.Packet.Length.Mean', 'Bwd.Packet.Length.Std', 'Flow.Bytes.s', 'Flow.Packets.s', 'Flow.IAT.Mean', 'Flow.IAT.Std', 'Flow.IAT.Max', 'Flow.IAT.Min', 'Fwd.IAT.Total', 'Fwd.IAT.Mean', 'Fwd.IAT.Std', 'Fwd.IAT.Max', 'Fwd.IAT.Min', 'Bwd.IAT.Total', 'Bwd.IAT.Mean', 'Bwd.IAT.Std', 'Bwd.IAT.Max', 'Bwd.IAT.Min', 'Fwd.PSH.Flags', 'Bwd.PSH.Flags', 'Fwd.URG.Flags', 'Bwd.URG.Flags', 'Fwd.Header.Length', 'Bwd.Header.Length', 'Fwd.Packets.s', 'Bwd.Packets.s', 'Min.Packet.Length', 'Max.Packet.Length', 'Packet.Length.Mean', 'Packet.Length.Std', 'Packet.Length.Variance', 'FIN.Flag.Count', 'SYN.Flag.Count', 'RST.Flag.Count', 'PSH.Flag.Count', 'ACK.Flag.Count', 'URG.Flag.Count', 'CWE.Flag.Count', 'ECE.Flag.Count', 'Down.Up.Ratio', 'Average.Packet.Size', 'Avg.Fwd.Segment.Size', 'Avg.Bwd.Segment.Size', 'Fwd.Header.Length.1', 'Fwd.Avg.Bytes.Bulk', 'Fwd.Avg.Packets.Bulk', 'Fwd.Avg.Bulk.Rate', 'Bwd.Avg.Bytes.Bulk', 'Bwd.Avg.Packets.Bulk', 'Bwd.Avg.Bulk.Rate', 'Subflow.Fwd.Packets', 'Subflow.Fwd.Bytes', 'Subflow.Bwd.Packets', 'Subflow.Bwd.Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active.Mean', 'Active.Std', 'Active.Max', 'Active.Min', 'Idle.Mean', 'Idle.Std', 'Idle.Max', 'Idle.Min', 'L7Protocol']
'''


## Helper funcitons

# S' is a Pandas Dataframe based on S and cfss, k is no. of clusters.
def k_means(Sdash, k) -> list:
    kmeans = KMeans(n_clusters=k, random_state=0).fit(Sdash)
    return kmeans.labels_

# C is set of clusters, k is no. of clusters, i is the for loop variant, label is set of class labels.
def calcEntropy(C,k,app,label):
  classes = [[] for i in range(K_FOR_KMEANS)]
  for i, sample in enumerate(C):
    classes[sample].append(i)
  print(classes)
  print()
  EC=0
  BC={m:[0,0] for m in range(k)}
  for m in range(len(C)):
    BC[C[m]][1]+=1
    if label[m]==app:
      BC[C[m]][0]+=1
  for j in range(k):
    try:
      Pij=BC[j][0]/BC[j][1]
      Qij=1-Pij
      if(Pij==0 or Qij==0):
        Ecj = 0.5
      else:
        Ecj=((-1)/math.log(2))*(Pij*math.log(Pij,2)+Qij*math.log(Qij,2))
      EC+=BC[j][1]*Ecj
    except Exception as error:
      # classes = [[] for i in range(K_FOR_KMEANS)]
      # for i, sample in enumerate(C):
      #   classes[sample].append(i)
      # print(classes)
      # print(j)
      raise error
  EC=EC/k
  return EC

def mergeCFSS(CFSSdash: list) -> list:
  res = []
  for i in range(0, len(CFSSdash)-1, 2):
    res.append(CFSSdash[i].union(CFSSdash[i+1]))
  if(len(CFSSdash)%2==1):
    res.append(CFSSdash[len(CFSSdash)-1])
  return res


## Algorithm for feature subspace selection
for app in APPS:
    print("starting for", app)
    CFSS = [{f} for f in F]
    dim = max(map(lambda x: len(x), CFSS))
    bestE = INT_MAX
    bestFSS = set()
    # Change the label as target and non-target
    # print(app, dim, M)
    while(dim < M):
        E = [] # To store entropies of each cfss
        for cfss in CFSS:
            Sdash = S[list(cfss)].copy()
            C = k_means(Sdash, K_FOR_KMEANS)
            print(cfss)
            E.append(calcEntropy(C, K_FOR_KMEANS, app, S.ProtocolName))
        minE = min(E)
        avgE = sum(E) / len(E) #TODO update this using a numpy function for efficieny
        if(minE >= bestE):
            break
        else:
            bestE = minE
            bestFSS = CFSS[E.index(minE)]
            CFSSdash = [CFSS[i] for i in range(len(CFSS)) if(E[i] < avgE)]
            CFSSnew = mergeCFSS(CFSSdash)
            CFSS = CFSSnew
            dim = max(map(lambda x: len(x), CFSS))
    FSS.append(bestFSS)
print(FSS)
# Now FSS[i] contains feature subspace for ith appliation class

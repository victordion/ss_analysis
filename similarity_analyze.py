#!/usr/bin/python
from collections import defaultdict
import operator
import commands
import matplotlib.pyplot as plt
from graph_tool.all import *

with open("shadowsocks.log") as f:
  content = f.readlines()

# This is a list to store target hostnames in each log line
# Used for closeness calculations
host_name_arr = []

g = Graph(directed=False)
vp_hostname = g.new_vertex_property("string")
vp_occurance = g.new_vertex_property("double")
ep_closeness = g.new_edge_property("double")

# Insert all vertices into the graph
for line in content:
  if "connecting" in line:
    tokens = line.split()

    last_dot_index = tokens[4].rfind('.')
    second_last_dot_index = tokens[4].rfind('.', 0, last_dot_index)
    colon_index = tokens[4].index(':')

    if last_dot_index != -1 and colon_index != -1:
      # Extract the hostname in the form of "google.com"
      visited_hostname = tokens[4][second_last_dot_index + 1: colon_index]
      host_name_arr.append(visited_hostname)
      v = find_vertex(g, vp_hostname, visited_hostname)
      if len(v) > 0:
        assert (len(v) == 1)
        vp_occurance[v[0]] += 1
      else:
        v = g.add_vertex()
        vp_hostname[v] = visited_hostname
        vp_occurance[v] = 1

neighbor_len_threshold = 5

host_name_dict = defaultdict(int)
for name in host_name_arr:
  host_name_dict[name] += 1

sorted_hostnames_by_occurance = sorted(host_name_dict.items(), key=operator.itemgetter(1), reverse=True)
for tp in sorted_hostnames_by_occurance:
  print "%s - %f" % tp

for i in range(len(host_name_arr) - neighbor_len_threshold):
  for j in range(1, neighbor_len_threshold):
    if host_name_arr[i] != host_name_arr[i + j]:
      v1 = find_vertex(g, vp_hostname, host_name_arr[i])[0]
      v2 = find_vertex(g, vp_hostname, host_name_arr[i + j])[0]
      e = g.edge(v1, v2, add_missing=True)
      ep_closeness[e] += 1.0 / j
      # print host_name_arr[i] + '<-->' + host_name_arr[i+j]

# normalize the edge weight
for e in g.edges():
  s = e.source()
  t = e.target()
  ep_closeness[e] /= min(vp_occurance[s], vp_occurance[t])

print "Total edge number is " + str(g.num_edges())
print "Total vertex number is " + str(g.num_vertices())

# IMPORTANT: edge filter must be applied before vertex filter, because filtering vertices will cause edges to be filtered!!!
companion_threshold = 0.3
efilter = g.new_edge_property("bool")
efilter.a = [ep_closeness[e] > companion_threshold for e in g.edges()]
g.set_edge_filter(efilter)

vfilter = g.new_vertex_property("bool")
vfilter.a = [vp_occurance[v] > 100 for v in g.vertices()]
g.set_vertex_filter(vfilter)

# Other ways to draw the graph
'''
pos = arf_layout(g, max_iter=10)
pos = sfdp_layout(g)
graph_draw(g, pos, vertex_text=vp_hostname, vertex_size=10, vertex_font_size=3, edge_pen_width=ep_closeness, output="a.pdf")
'''

state = minimize_nested_blockmodel_dl(g, deg_corr=True)
draw_hierarchy(state, vertex_text=vp_hostname, vertex_size=10, vertex_text_position=3.14, vertex_font_size=5,
               edge_pen_width=ep_closeness, output="a.pdf")

set datafile separator ','
set key autotitle columnhead
set ylabel "latency, ms"
set xlabel 'N*2'

plot "results/memif_to_memif_23_to_1.txt" using 1:2 with lines, '' using 1:3 with lines, '' using 1:4 with lines, '' using 1:5 with lines, '' using 1:6 with lines, '' using 1:7 with lines, '' using 1:8 with lines, '' using 1:9 with lines, '' using 1:10 with lines, 

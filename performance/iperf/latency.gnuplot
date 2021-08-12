set datafile separator ','
set key autotitle columnhead
set ylabel "bandwidth, Mb/s"
set xlabel 'seconds'
set yrange [0:200]

plot "results/kernel_to_kernel_3_to_1.csv" using 1:2 with lines, '' using 1:3 with lines, '' using 1:4 with lines, '' using 1:5 with lines, '' using 1:6 with lines, 

INPUT_FILE="results/kernel_to_kernel_3_to_1.csv"
LINES_COUNT=$(head -n 1 ${INPUT_FILE} | tr -s ',' '\n\n\n' | wc -w)

LINES=""
for (( i = 3; i <= LINES_COUNT; i++ )); do
    LINES+="'' using 1:${i} with lines, "
done

cat > latency.gnuplot << EOF
set datafile separator ','
set key autotitle columnhead
set ylabel "bandwidth, Mb/s"
set xlabel 'seconds'
set yrange [0:200]

plot "${INPUT_FILE}" using 1:2 with lines, ${LINES}
EOF

gnuplot -p latency.gnuplot
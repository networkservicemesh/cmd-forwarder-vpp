INPUT_FILE="results/memif_to_memif_23_to_1.txt"

LINES=""
LINES_COUNT=$(head -n 1 ${INPUT_FILE} | tr -s ',' '\n\n\n' | wc -w)
for (( i = 3+0*LINES_COUNT/2; i < LINES_COUNT/2; i++ )); do
    LINES+="'' using 1:${i} with lines, "
done

cat > latency.gnuplot << EOF
set datafile separator ','
set key autotitle columnhead
set ylabel "latency, ms"
set xlabel 'N*2'

plot "${INPUT_FILE}" using 1:2 with lines, ${LINES}
EOF

gnuplot -p latency.gnuplot
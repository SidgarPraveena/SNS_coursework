count=0
while true; do	
	printf 'count=%d\n' "$count"
	count=$((count+1))
	./bin3 dummy.pgn praveena
done

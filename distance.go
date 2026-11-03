package robertparker

//Distance functions that compute the distance between two strings.

//Levenshtein computes the edit distance between two domain strings, counting Unicode characters rather than bytes.
func Levenshtein(s1, s2 string) int {
	d1, d2 := []rune(s1), []rune(s2)
	d := make([][]int, len(d1)+1)
	for i := range d {
		d[i] = make([]int, len(d2)+1)
	}
	for i := range d {
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for j := 1; j <= len(d2); j++ {
		for i := 1; i <= len(d1); i++ {
			if d1[i-1] == d2[j-1] {
				d[i][j] = d[i-1][j-1]
			} else {
				min := d[i-1][j]
				if d[i][j-1] < min {
					min = d[i][j-1]
				}
				if d[i-1][j-1] < min {
					min = d[i-1][j-1]
				}
				d[i][j] = min + 1
			}
		}
	}
	return d[len(d1)][len(d2)]
}

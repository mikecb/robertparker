package main

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func writeLines(d Domain, filename string) err error {
        f, err := os.Create(filename)
        if err != nil {
                panic(err)
        }

        defer f.Close()

        b, err := json.MarshalIndent(d, "", "    ")
        if err != nil {
                return err
        }

        w := bufio.NewWriter(f)
        _, err := w.WriteString(b)
        w.Flush()
}

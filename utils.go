package cors

// Searches for a string in a given slice.
func stringInSlice(target string, list []string) bool {
	for _, value := range list {
		if target == value {
			return true
		}
	}

	return false
}

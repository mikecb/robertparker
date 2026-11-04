package robertparker

import "context"

//Findings are what the checks report about a domain, and grades are what those findings add up to.

// Severity says how much a Finding matters.
type Severity string

const (
	SeverityInfo    Severity = "info"    //Worth knowing, with no effect on the grade.
	SeverityWarning Severity = "warning" //Falls short of best practice.
	SeverityFailure Severity = "failure" //Broken, or missing protection.
	SeverityUnknown Severity = "unknown" //The check couldn't finish, for example because of a DNS timeout, so nothing is known.
)

// Finding is one thing a check found about a domain.
type Finding struct {
	Check    string   //A stable ID for the check, e.g. "spf-all".
	Severity Severity //How much it matters.
	Message  string   //What was found, for people.
	Standard string   //Where the requirement comes from, e.g. "RFC 7208".
}

// Grading starts at 100 and takes off a penalty per finding, so one warning costs a letter and one failure costs most
// of them. These are the numbers to change to make grading stricter or more lenient.
const (
	warningPenalty = 15
	failurePenalty = 40
)

// gradeBands are the lowest scores for each grade, highest first. Anything lower is an F.
var gradeBands = []struct {
	min   int
	grade string
}{{90, "A"}, {80, "B"}, {70, "C"}, {60, "D"}}

// Grade works out a letter grade from a domain's findings, and stores it in d.Grade. A domain gets no grade if any
// check couldn't finish, since a grade that ignored it would be a guess, or if it has no registrable domain to check.
func Grade(d *Domain) string {
	d.Grade = ""
	if d.Secondary == "" {
		return ""
	}
	score := 100
	for _, f := range d.Findings {
		switch f.Severity {
		case SeverityUnknown:
			return ""
		case SeverityWarning:
			score -= warningPenalty
		case SeverityFailure:
			score -= failurePenalty
		}
	}
	d.Grade = "F"
	for _, b := range gradeBands {
		if score >= b.min {
			d.Grade = b.grade
			break
		}
	}
	return d.Grade
}

// GradeAnalyzer is an Analyzer that runs Grade. It goes after the analyzers that add findings.
func GradeAnalyzer(_ context.Context, d *Domain) error {
	Grade(d)
	return nil
}

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
	Area     string   //The part of the domain's setup it's about, e.g. "email". Each area is graded separately.
	Check    string   //A stable ID for the check, e.g. "spf-all".
	Severity Severity //How much it matters.
	Message  string   //What was found, for people.
	Standard string   //Where the requirement comes from, e.g. "RFC 7208".
}

// Grading starts each area at 100 and takes off a penalty per check that found something, so one warning costs a letter
// and one failure costs most of them. These are the numbers to change to make grading stricter or more lenient.
//
// Web and DNS warnings cost less because there are many more of them, and most are about hardening rather than something
// wrong. At the email penalty, wikipedia.org, microsoft.com, and mozilla.org all got an F for the web, and tesla.com got
// one for DNS that works, which says nothing.
const (
	warningPenalty          = 15
	hardeningWarningPenalty = 10
	failurePenalty          = 40
)

// gradeBands are the lowest scores for each grade, highest first. Anything lower is an F.
var gradeBands = []struct {
	min   int
	grade string
}{{90, "A"}, {80, "B"}, {70, "C"}, {60, "D"}}

// Checked records that an area was checked, so it gets a grade even if the checks found nothing. Analyzers call it
// when they have something to check. An area that doesn't apply, like the web on a domain with no web server, stays
// ungraded rather than getting credit for having nothing wrong.
func (d *Domain) Checked(area string) {
	for _, a := range d.areas {
		if a == area {
			return
		}
	}
	d.areas = append(d.areas, area)
}

// Grade works out a letter grade for each area that was checked, stored in d.Grades, and an overall grade, stored in
// d.Grade and returned. The overall grade is the worst of the areas, because a strong area doesn't make up for a weak
// one: good email settings don't help if the certificate has expired.
//
// An area gets no grade if any of its checks couldn't finish, since a grade that ignored them would be a guess, and
// then there's no overall grade either. There's no grade at all if nothing was checked.
func Grade(d *Domain) string {
	d.Grade, d.Grades = "", nil
	worst, complete := "", true
	for _, area := range d.areas {
		grade := gradeArea(d, area)
		if grade == "" {
			complete = false
			continue
		}
		if d.Grades == nil {
			d.Grades = map[string]string{}
		}
		d.Grades[area] = grade
		if grade > worst {
			worst = grade // Letters sort from best to worst.
		}
	}
	if complete {
		d.Grade = worst
	}
	return d.Grade
}

// gradeArea returns the grade for one area, or "" if one of its checks couldn't finish.
func gradeArea(d *Domain, area string) string {
	warning := warningPenalty
	if area == AreaWeb || area == AreaDNS {
		warning = hardeningWarningPenalty
	}
	// One problem can be found several ways, so each check costs once, at its worst.
	penalties := map[string]int{}
	for _, f := range d.Findings {
		if f.Area != area {
			continue
		}
		penalty := 0
		switch f.Severity {
		case SeverityUnknown:
			return ""
		case SeverityWarning:
			penalty = warning
		case SeverityFailure:
			penalty = failurePenalty
		}
		penalties[f.Check] = max(penalties[f.Check], penalty)
	}
	score := 100
	for _, penalty := range penalties {
		score -= penalty
	}
	for _, b := range gradeBands {
		if score >= b.min {
			return b.grade
		}
	}
	return "F"
}

// GradeAnalyzer is an Analyzer that runs Grade. It goes after the analyzers that add findings.
func GradeAnalyzer(_ context.Context, d *Domain) error {
	Grade(d)
	return nil
}

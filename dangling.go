package robertparker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/publicsuffix"
)

//Dangling CNAMEs. A CNAME that outlives what it points to hands the name to whoever claims the target next, who can then
//serve anything under the domain, with cookies and all. Only the zone's owner can list its names, so this looks at the
//names most often in use, with the same queries a browser's resolver sends.

// danglingWorkers is how many names of one domain to look up at once.
const danglingWorkers = 6

// commonSubdomains are the names to look at. Of 1,641 domains surveyed with these, 26 CNAMEs were dangling, spread over
// most of the list.
var commonSubdomains = []string{
	"www", "m", "mail", "email", "blog", "news", "media", "shop", "store", "docs", "help", "support", "status",
	"careers", "jobs", "portal", "admin", "login", "vpn", "api", "app", "dev", "staging", "test", "cdn", "static",
	"assets", "images", "click", "go", "link", "info",
}

// claimableServices are services where anyone can sign up for a name that doesn't exist, so a CNAME to one that's gone
// can be taken over, with how many labels come before the suffix. The list is the services marked vulnerable with an
// NXDOMAIN signal at https://github.com/EdOverflow/can-i-take-over-xyz, plus Traffic Manager, from Microsoft's advice on
// dangling records. Longer names are generated, like Elastic Beanstalk's name.random.region, so nobody can ask for them.
var claimableServices = []struct {
	suffix string
	labels int
}{
	{"azure-api.net", 1},
	{"azurecontainer.io", 2}, //name.region
	{"azurecr.io", 1},
	{"azuredatalakestore.net", 1},
	{"azureedge.net", 1},
	{"azurehdinsight.net", 1},
	{"azurewebsites.net", 1},
	{"blob.core.windows.net", 1},
	{"cloudapp.azure.com", 2}, //name.region
	{"cloudapp.net", 1},
	{"database.windows.net", 1},
	{"elasticbeanstalk.com", 2}, //name.region, or just name in old ones.
	{"redis.cache.windows.net", 1},
	{"search.windows.net", 1},
	{"servicebus.windows.net", 1},
	{"trafficmanager.net", 1},
	{"trydiscourse.com", 1},
	{"visualstudio.com", 1},
}

// claimableService reports whether a name that doesn't exist can be signed up for.
func claimableService(name string) bool {
	return slices.ContainsFunc(claimableServices, func(service struct {
		suffix string
		labels int
	}) bool {
		front, found := strings.CutSuffix(name, "."+service.suffix)
		return found && strings.Count(front, ".") < service.labels
	})
}

// dangling is a name whose CNAME leads to a name that doesn't exist.
type dangling struct {
	name   string
	target string
}

// followCNAME looks up name, and returns the end of its CNAMEs if that doesn't exist.
func (c *dnsChecker) followCNAME(ctx context.Context, name string) (dangling, bool) {
	reply, err := c.lookup.query(ctx, name, dnsmessage.TypeA, false)
	if err != nil || reply.header.RCode != dnsmessage.RCodeNameError {
		return dangling{}, false // A name that can't be looked up may be broken, but nothing says that it's up for grabs.
	}
	var target string
	for _, answer := range reply.answers {
		if alias, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			target = presentName(alias.CNAME)
		}
	}
	return dangling{name, target}, target != ""
}

// checkDangling looks for CNAMEs that point to names that don't exist. How much that matters depends on who can claim
// the name. If the target's domain isn't registered, or it's on a service that gives names out, anyone can, and that's
// a failure. Under the domain itself, nobody else can, so the record is only out of date. Anywhere else, it depends on
// the provider, which can't be seen from here. 11 of 1,641 domains surveyed had one of those, and none had a target
// that anyone could claim, so a warning is about right, and a failure should be rare.
func (c *dnsChecker) checkDangling(ctx context.Context) error {
	names := make([]string, 0, len(commonSubdomains)+1)
	for _, label := range commonSubdomains {
		names = append(names, label+"."+c.zone)
	}
	if host := c.domain.hostname(); host != c.zone && !slices.Contains(names, host) {
		names = append(names, host)
	}

	results := make([]dangling, len(names))
	work := make(chan int)
	var wait sync.WaitGroup
	for range danglingWorkers {
		wait.Go(func() {
			for i := range work {
				if found, ok := c.followCNAME(ctx, names[i]); ok {
					results[i] = found
				}
			}
		})
	}
	for i := range names {
		work <- i
	}
	close(work)
	wait.Wait()

	deadline, limited := ctx.Deadline()
	if ctx.Err() != nil || limited && !time.Now().Before(deadline) {
		c.add("dns-dangling", SeverityUnknown, "", "Ran out of time looking up the domain's subdomains.")
		return fmt.Errorf("ran out of time looking up the subdomains of %s", c.zone)
	}

	// Names that share a target are one mistake, which a wildcard can make look like many.
	var targets []string
	byTarget := map[string][]string{}
	for _, found := range results {
		if found.target == "" {
			continue
		}
		if byTarget[found.target] == nil {
			targets = append(targets, found.target)
		}
		byTarget[found.target] = append(byTarget[found.target], found.name)
	}
	var errs error
	for _, target := range targets {
		if err := c.judgeDangling(ctx, strings.Join(byTarget[target], ", "), target); err != nil && errs == nil {
			errs = err
		}
	}
	return errs
}

// judgeDangling reports names that point to target, which doesn't exist.
func (c *dnsChecker) judgeDangling(ctx context.Context, names, target string) error {
	registrable, _ := publicsuffix.EffectiveTLDPlusOne(target)
	suffix, icann := publicsuffix.PublicSuffix(target)
	switch {
	case registrable == c.zone:
		c.add("dns-dangling", SeverityInfo, "", fmt.Sprintf("%s points to %s, which doesn't exist. It's under this domain, so nobody else can claim it, and the record is only out of date.", names, target))
		return nil
	case claimableService(target):
		c.add("dns-dangling", SeverityFailure, "", fmt.Sprintf("%s points to %s, which doesn't exist, on a service where anyone can sign up for a name, so whoever signs up for it controls %s.", names, target, names))
		return nil
	case icann && strings.Contains(target, ".") && registrable != "" && registrable != suffix:
		reply, err := c.lookup.query(ctx, registrable, dnsmessage.TypeNS, false)
		if err != nil {
			c.add("dns-dangling", SeverityUnknown, "", fmt.Sprintf("Couldn't look up %s, which %s points to: %v", registrable, names, err))
			return fmt.Errorf("DNS lookup of %s: %w", registrable, err)
		}
		if reply.header.RCode == dnsmessage.RCodeNameError {
			c.add("dns-dangling", SeverityFailure, "", fmt.Sprintf("%s points to %s, and %s doesn't seem to be registered, so whoever registers it controls %s.", names, target, registrable, names))
			return nil
		}
	}
	c.add("dns-dangling", SeverityWarning, "", fmt.Sprintf("%s points to %s, which doesn't exist. Remove the record, since it can be taken over if the provider lets anyone claim that name.", names, target))
	return nil
}

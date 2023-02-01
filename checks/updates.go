package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/google/go-github/github"
	"github.com/kubearmor/kubearmor-client/selfupdate"
)

type UpdateChecker struct {
	Client *github.Client
}

func (c *UpdateChecker) FetchReleases() ([]*github.RepositoryRelease, error) {
	releases, _, err := c.Client.Repositories.ListReleases(context.Background(),
		"PrimalPimmy",
		"kubearmor-client",
		&github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Error fetching releases from GitHub: %v", err)
	}
	return releases, nil
}

func (c *UpdateChecker) GetLatestMandatoryRelease(releases []*github.RepositoryRelease) (*github.RepositoryRelease, error) {
	var latestMandatoryRelease *github.RepositoryRelease
	for _, release := range releases {
		if strings.Contains(*release.Body, "mandatory") || strings.Contains(*release.Body, "MANDATORY") {
			latestMandatoryRelease = release
			break
		}
	}
	if latestMandatoryRelease == nil {
		return nil, nil
	}
	return latestMandatoryRelease, nil
}

func (c *UpdateChecker) CompareVersions(currentVersion string, latestMandatoryRelease *github.RepositoryRelease) error {
	if latestMandatoryRelease == nil {
		color.HiGreen("The client is up to date.")
		return nil
	}
	if !strings.EqualFold(currentVersion, *latestMandatoryRelease.TagName) {
		color.HiMagenta("A mandatory update is available (current version: %s, latest release: %s).\n",
			currentVersion,
			*latestMandatoryRelease.TagName,
		)
	} else {
		fmt.Println("The client is up to date.")
	}
	return nil
}

func (c *UpdateChecker) CheckForUpdates() error {
	releases, err := c.FetchReleases()
	if err != nil {
		return err
	}

	latestMandatoryRelease, err := c.GetLatestMandatoryRelease(releases)
	if err != nil {
		return err
	}

	currentVersion := selfupdate.GitSummary
	err = c.CompareVersions(currentVersion, latestMandatoryRelease)
	if err != nil {
		return fmt.Errorf("Error comparing versions: %v", err)
	}
	return nil
}

func NewUpdateChecker() *UpdateChecker {
	return &UpdateChecker{
		Client: github.NewClient(nil),
	}
}

func (c *UpdateChecker) Init() error {
	err := c.CheckForUpdates()
	if err != nil {
		return err
	}
	return nil
}

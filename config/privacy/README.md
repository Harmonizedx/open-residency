# Regulatory profiles

One file per country, named by the ISO 3166-1 alpha-2 code (`NG.json`): the data-protection
authority, the grounds on which an impact assessment is required before processing, the
retention rule where no statutory period is set, the third-party-sharing rule, the
breach-notification clock, and a hosting note. These are data, not code: the compliance
generators in the core evaluate generic conditions (always, biometrics configured, vulnerable
subjects, automated decisions permitted, new technology) and take the words and citations from
here, so the core knows no country's law.

A country with no profile gets a neutral one: "the applicable data-protection law", no article
citations, and a 72-hour breach clock. Verify every citation against the current text before
filing anything; the review that produced the Nigerian profile marked its sources.

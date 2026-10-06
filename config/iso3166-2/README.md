# ISO 3166-2 subdivision tables

One file per country, named by the ISO 3166-1 alpha-2 code (`NG.json`), holding the
subdivision codes ISO 3166-2 assigns for that country, keyed by the suffix after the country
prefix. These are data, not code: the core reads whichever tables are present and branches on
none of them.

A table lets the country-config loader report, at start-up, a declared unit code or
`iso3166_2` value that ISO does not assign for that country. It is a warning surface, not a
gate: wards and local-government areas are not in ISO, and a jurisdiction's own scheme is
legitimate. What it catches is a state code typed wrong, or declared in one form in the config
and another in the register it will be reconciled against.

Add a country by adding its file in the same shape. Sources: the ISO Online Browsing Platform
entry for the country.

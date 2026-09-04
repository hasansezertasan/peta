# External API contract fixtures

These sanitized fixtures contain only fields Peta consumes plus one unknown
field to verify forward compatibility. They must never contain credentials,
private package data, or personal information.

To refresh a fixture deliberately:

1. Save a current response from the provider named by the fixture.
2. Remove all unconsumed fields except one representative unknown field.
3. Replace names, URLs, advisory identifiers, and counts with stable synthetic
   values while preserving JSON types and nesting.
4. Run the corresponding unit test and the full test matrix.

Do not update a fixture merely to make a failing parser test pass. Confirm the
provider's published contract and decide explicitly whether the upstream change
is backward compatible first.

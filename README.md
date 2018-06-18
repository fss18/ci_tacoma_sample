### Cloud Insight Tacoma - Report Download Sample

This is an example on how to utilize Insight Tacoma API in order to download Cloud Insight reports and perform manipulation as needed.

## Usage
Sample run:
```
python3 ci_tacoma_sample.py --user first.last@company.com --pswd my_insight_password --cid target_cid --mode ALL --dc defender-us-denver
```

## Arguments
| Argument | Description |
| ------------- |-------------|
| --user | User name / email address for Insight API Authentication |
| --pswd | Password for Insight API Authentication |
| --dc | Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport |
| --cid | Target Alert Logic Customer ID for processing |
| --mode | Set to ALL to download all fields, use LIMITED for filtering specific fields |

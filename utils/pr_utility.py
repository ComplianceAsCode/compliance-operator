import argparse
import json
import os, fileinput

def parse_description(description_file):
    # Read the description file
    with open(description_file, 'r') as f:
        description = f.read()
    
    # Initialize the JSON object
    json_data = {
        'description': '',
        'change_type': {
            'enhancements': False,
            'fixes': False,
            'internal_changes': False,
            'deprecations': False,
            'removals': False,
            'security': False,
            'not_applicable': False
        },
        'testing': {
            'unit_test': False,
            'e2e_test': False,
            'manual_test': False,
            'not_applicable': False
        }
    }

    # Parse the description from the input
    for line in description.split('\n'):
        if line.startswith('## Description'):
            continue
        elif line.startswith('## Type of change'):
            break
        else:
            json_data['description'] += line

    # Check description is templated text "Please include a summary of the changes and the related issue." or empty
    if json_data['description'] == 'Please include a summary of the changes and the related issue.' or json_data['description'] == '':
        raise ValueError("Description is empty or templated text.")
    
    # Initialize the change types
    change_types = {
        'Enhancements (Adds functionality)': 'enhancements',
        'Fixes (Fixes an issue, please reference the issue)': 'fixes',
        'Internal Changes (Documentation, Tests, etc.)': 'internal_changes',
        'Deprecations (Signals removal of a feature)': 'deprecations',
        'Removals (Removes a feature)': 'removals',
        'Security (Fixes a vulnerability)': 'security',
        'No Changelog(Release PR, Changelog PR, this PR will not be added to the changelog)': 'not_applicable'
    }

    # Parse change types from the input
    for line in description.split('\n'):
        for key, value in change_types.items():
            if line.startswith(f'- [x] {key}'):
                json_data['change_type'][value] = True
    
    # Perform input validation for change types
    # Only one can be selected
    if not any(json_data['change_type'].values()):
        raise ValueError("No change type selected.")
    elif sum(json_data['change_type'].values()) > 1:
        raise ValueError("Only one change type can be selected.")

    # Initialize the testing types
    testing_types = {
        'Unit Test': 'unit_test',
        'E2E Test': 'e2e_test',
        'Manual Test': 'manual_test',
        'Not Applicable': 'not_applicable'
    }

    # Parse testing types from the input
    for line in description.split('\n'):
        for key, value in testing_types.items():
            if line.startswith(f'- [x] {key}'):
                json_data['testing'][value] = True

    # Perform input validation for testing types
    if not any(json_data['testing'].values()):
        raise ValueError("No testing type selected.")
    elif json_data['testing']['not_applicable'] and any(json_data['testing'].values()) and sum(json_data['testing'].values()) > 1:
        raise ValueError("Not Applicable cannot be selected with other testing types.")

    # Output the JSON object
    return json.dumps(json_data, indent=4)

def match_pr_type_to_changelog_section(pr_type):
    # Initialize the change types
    change_types = {
        'enhancements': 'Enhancements',
        'fixes': 'Fixes',
        'internal_changes': 'Internal Changes',
        'deprecations': 'Deprecations',
        'removals': 'Removals',
        'security': 'Security'
    }
    # Return the matching changelog section
    return change_types[pr_type]

def insert_changelog_entry(description_json_file, changelog_file, pr_number):
    # Parse the json description from the input file
    with open(description_json_file, 'r') as f:
        json_data = json.load(f)


    # Get the change type
    change_type = ''
    for key, value in json_data['change_type'].items():
        if value:
            change_type = key

    # Get the description
    description = json_data['description']

    # Insert the new entry under the section for the given change type
    with open(changelog_file, 'r+') as f:
        # Read the file
        changelog = f.read()

        # Find the Unreleased section
        unreleased_index = changelog.find(f"\n## Unreleased\n")

        if unreleased_index == -1:
            raise ValueError("Changelog Unreleased section not found.")

        nextrelease_index = changelog.find(f"\n## [")

        if nextrelease_index == -1:
            nextrelease_index = len(changelog)

        changelog_type = match_pr_type_to_changelog_section(change_type)

        # Find the section for the given change type
        section_index = changelog.find(f"\n### {changelog_type}\n", unreleased_index, nextrelease_index)

        if section_index == -1:
            raise ValueError("Changelog section not found.")
        

        nextpond_index = changelog.find(f"\n##", section_index+1)

        if nextpond_index == -1:
            nextpond_index = len(changelog)

        new_entry = f"\n- {description} (#{pr_number})\n\n"

        next_entry_index = changelog.find(f"\n- ", section_index-1, nextpond_index)

        if next_entry_index == -1:
            if nextpond_index == nextrelease_index:
                secondhalf_index = nextpond_index
            else:
                secondhalf_index = nextpond_index + 1
        else:
            secondhalf_index = next_entry_index + 1
         
        first_half = changelog[:section_index + len(f"\n### {changelog_type}\n")]

        second_half = changelog[secondhalf_index:]

        changelog = first_half + new_entry + second_half

        # Write the file
        f.seek(0)
        f.write(changelog)


        


        
        

    
    

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='PR changelog utility')
    parser.add_argument('-i', '--input', type=str, help='Description file')
    parser.add_argument('-p', '--parse', action='store_true', help='Parse the description from the input file')
    parser.add_argument('-u', '--update', action='store_true', help='Update the changelog file with the entry from the input file')
    parser.add_argument('-c', '--changelog', type=str, help='Changelog file')
    parser.add_argument('-pr', '--number', type=str, help='PR number')


    args = parser.parse_args()

    if args.parse:
        if args.input:
            print(parse_description(args.input))
        else:
            print("Input file not specified.")
    elif args.update:
        if args.input and args.changelog and args.number:
            insert_changelog_entry(args.input, args.changelog, args.number)
        else:
            print("Input file, changelog file, or PR number not specified.")
    else:
        parser.print_help()

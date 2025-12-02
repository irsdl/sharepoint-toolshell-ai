"""
Clean markdown files for AI RAG by removing navigation, UI elements, and marketing content.
Preserves YAML frontmatter and technical content.
"""

import re
import os
from pathlib import Path
from typing import List, Tuple


class MarkdownCleaner:
    """Clean markdown files for RAG purposes"""

    # Common navigation patterns to remove
    NAV_PATTERNS = [
        r'^(About|Blog|Advisories|Exploits|Research|Training|Contact|Home|Publications|Achievements|Search)\s*$',
        r'^(Menu|PRIVACY|WHO WE ARE|HOW IT WORKS|ADVISORIES|LOG IN|SIGN UP)\s*$',
        r'^(Business|Platform|Products?|Solutions?|Resources?|Support)\s*$',
        r'^(Syllabus|Prerequisites|Challenge|Schedule/Signup|Testimonials|Faq)\s*$',
        r'^search close\s*$',
        r'^SUBSCRIBE\s*$',
        r'^\s*(Home|About|Blog|Advisories)\s+(Blog|Advisories|Exploits|Research)\s+.*$',
        # Match lines with multiple navigation terms (like "Syllabus Prerequisites Challenge...")
        r'^[\s\w/]*(Syllabus|Prerequisites|Challenge|Testimonials|Faq)[\s\w/]+(Syllabus|Prerequisites|Challenge|Testimonials|Faq).*$',
        r'^[\s\w]*(Home|About|Blog|Advisories|Publications)[\s\w]+(Home|About|Blog|Advisories|Publications).*$',
    ]

    # Marketing/product sections to remove (multi-line)
    MARKETING_SECTIONS = [
        # Trend Micro product marketing
        (r'^(Trend Vision One|Platform|Security Operations|Cloud Security|Endpoint Security|XDR)',
         r'^(Learn more|View all|Get started|Try now|Contact us)\s*$'),
        # Generic marketing sections
        (r'^(Our Products?|Our Solutions?|Why Choose|Key Features)',
         r'^(Learn more|Get started|Contact|View all)\s*$'),
    ]

    # Footer patterns
    FOOTER_PATTERNS = [
        r'^copyright\s*©.*$',
        r'^The content of this site is licensed under.*$',
        r'^pgp key\s*$',
        r'^sourceincite\s*$',
    ]

    # Patterns for lines that are just UI elements
    UI_ELEMENT_PATTERNS = [
        r'^(Table of Contents|TOC)\s*$',
        r'^View fullsize\s*$',
        r'^Figure \d+\s*:?\s*$',
    ]

    def __init__(self):
        self.nav_regex = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.NAV_PATTERNS]
        self.footer_regex = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.FOOTER_PATTERNS]
        self.ui_regex = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.UI_ELEMENT_PATTERNS]

    def extract_frontmatter(self, content: str) -> Tuple[str, str]:
        """Extract YAML frontmatter from markdown content"""
        if not content.startswith('---'):
            return '', content

        parts = content.split('---', 2)
        if len(parts) < 3:
            return '', content

        frontmatter = f"---{parts[1]}---"
        body = parts[2]
        return frontmatter, body

    def remove_duplicate_titles(self, lines: List[str], title_from_frontmatter: str = None) -> List[str]:
        """Remove duplicate titles, especially at the start of content"""
        if not lines:
            return lines

        # Remove empty lines at the start
        while lines and not lines[0].strip():
            lines.pop(0)

        # If we have a title from frontmatter, remove duplicate occurrences
        if title_from_frontmatter:
            title_clean = title_from_frontmatter.strip('"\'')
            # Remove up to 2 occurrences of the same title at the start
            removed_count = 0
            while lines and removed_count < 2:
                first_line = lines[0].strip()
                # Remove markdown heading markers
                first_line_clean = first_line.lstrip('#').strip()
                if first_line_clean == title_clean:
                    lines.pop(0)
                    removed_count += 1
                    # Remove trailing empty line
                    while lines and not lines[0].strip():
                        lines.pop(0)
                else:
                    break

        return lines

    def is_navigation_line(self, line: str) -> bool:
        """Check if a line is a navigation element"""
        stripped = line.strip()
        if not stripped:
            return False

        for regex in self.nav_regex:
            if regex.match(stripped):
                return True

        for regex in self.ui_regex:
            if regex.match(stripped):
                return True

        return False

    def is_footer_line(self, line: str) -> bool:
        """Check if a line is a footer element"""
        stripped = line.strip()
        if not stripped:
            return False

        for regex in self.footer_regex:
            if regex.match(stripped):
                return True

        return False

    def remove_marketing_sections(self, lines: List[str]) -> List[str]:
        """Remove marketing sections that span multiple lines"""
        cleaned = []
        in_marketing = False
        marketing_level = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Check if we're starting a marketing section
            if not in_marketing:
                for start_pattern, _ in self.MARKETING_SECTIONS:
                    if re.match(start_pattern, stripped, re.IGNORECASE):
                        in_marketing = True
                        marketing_level = 0
                        break

            # If in marketing section, look for end or continue
            if in_marketing:
                marketing_level += 1
                # End marketing section after reasonable number of lines or specific patterns
                for _, end_pattern in self.MARKETING_SECTIONS:
                    if re.match(end_pattern, stripped, re.IGNORECASE):
                        in_marketing = False
                        break

                # Also end if we see a heading or substantial content after some lines
                if marketing_level > 20 or (marketing_level > 5 and len(stripped) > 100):
                    in_marketing = False
                    cleaned.append(line)

                continue

            cleaned.append(line)

        return cleaned

    def clean_body(self, body: str, title: str = None) -> str:
        """Clean the markdown body of navigation and marketing content"""
        lines = body.split('\n')

        # Remove duplicate titles
        lines = self.remove_duplicate_titles(lines, title)

        # Remove navigation and UI lines
        lines = [line for line in lines if not self.is_navigation_line(line)]

        # Remove footer lines
        lines = [line for line in lines if not self.is_footer_line(line)]

        # Remove marketing sections
        lines = self.remove_marketing_sections(lines)

        # Remove excessive blank lines (more than 2 consecutive)
        cleaned_lines = []
        blank_count = 0
        for line in lines:
            if not line.strip():
                blank_count += 1
                if blank_count <= 2:
                    cleaned_lines.append(line)
            else:
                blank_count = 0
                cleaned_lines.append(line)

        # Remove leading/trailing whitespace
        while cleaned_lines and not cleaned_lines[0].strip():
            cleaned_lines.pop(0)
        while cleaned_lines and not cleaned_lines[-1].strip():
            cleaned_lines.pop()

        return '\n'.join(cleaned_lines)

    def clean_file(self, filepath: Path) -> Tuple[bool, str]:
        """
        Clean a single markdown file
        Returns: (success, message)
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract frontmatter
            frontmatter, body = self.extract_frontmatter(content)

            # Extract title from frontmatter if available
            title = None
            if frontmatter:
                title_match = re.search(r'^title:\s*["\']?([^"\']+)["\']?\s*$', frontmatter, re.MULTILINE)
                if title_match:
                    title = title_match.group(1)

            # Clean the body
            cleaned_body = self.clean_body(body, title)

            # Reconstruct the file
            if frontmatter:
                cleaned_content = f"{frontmatter}\n\n{cleaned_body}\n"
            else:
                cleaned_content = f"{cleaned_body}\n"

            # Write back
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(cleaned_content)

            return True, f"Cleaned successfully"

        except Exception as e:
            return False, f"Error: {str(e)}"


def main():
    """Main function to clean all markdown files in the writeups directory"""
    base_dir = Path(__file__).parent.parent.parent
    writeups_dir = base_dir / 'additional_resources' / 'previous_sp_related_writeups'

    if not writeups_dir.exists():
        print(f"Error: Directory not found: {writeups_dir}")
        return 1

    cleaner = MarkdownCleaner()
    md_files = list(writeups_dir.glob('*.md'))

    print(f"Found {len(md_files)} markdown files to clean")
    print("-" * 60)

    success_count = 0
    fail_count = 0

    for md_file in md_files:
        success, message = cleaner.clean_file(md_file)
        status = "[OK]" if success else "[FAIL]"
        print(f"{status} {md_file.name}: {message}")

        if success:
            success_count += 1
        else:
            fail_count += 1

    print("-" * 60)
    print(f"Completed: {success_count} succeeded, {fail_count} failed")

    return 0 if fail_count == 0 else 1


if __name__ == '__main__':
    exit(main())

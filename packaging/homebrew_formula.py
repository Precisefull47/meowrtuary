"""Generate a tap formula for an explicitly supplied release URL and checksum."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse


def formula(archive, url, version, homepage):
    if urlparse(url).scheme not in ('https', 'file'):
        raise ValueError('Use HTTPS for publication or file:// for local validation')
    if urlparse(homepage).scheme != 'https':
        raise ValueError('Homepage must use HTTPS')
    import re
    if not re.fullmatch(r'\d+\.\d+\.\d+',version):raise ValueError('Expected a three-part release version')
    sha=hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    # JSON string literals are compatible with Ruby; escape interpolation as well.
    def quote(value):return json.dumps(value).replace('#{',r'\#{')
    return f'''class Meowrtuary < Formula
  desc "Local LLM artifact acquisition and forensic analysis"
  homepage {quote(homepage)}
  url {quote(url)}
  version {quote(version)}
  sha256 "{sha}"

  license "MIT"

  depends_on :macos
  depends_on arch: :arm64

  def install
    libexec.install "bin"
    prefix.install "LICENSE", "THIRD_PARTY_NOTICES.md", "licenses"
    bin.install_symlink libexec/"bin/llm-forensics" => "meow"
  end

  def caveats
    "Run meow to open the menu. Full Disk Access must be granted separately when needed."
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/meow --version")
    system bin/"meow", "--doctor"
    system bin/"meow", "--self-test", "--output", testpath/"validation"
  end
end
'''

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--url',required=True)
    p.add_argument('--homepage',required=True)
    p.add_argument('--version',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    text=formula(a.archive,a.url,a.version,a.homepage)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:f.write(text)

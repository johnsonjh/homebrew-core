require "language/node"

class FirebaseCli < Formula
  desc "Firebase command-line tools"
  homepage "https://firebase.google.com/docs/cli/"
  url "https://registry.npmjs.org/firebase-tools/-/firebase-tools-3.18.0.tgz"
  sha256 "0e62e73ad90b96e52386c8c4ebf152b3209e249a09c9f9594ee33174575e0a12"
  head "https://github.com/firebase/firebase-tools.git"

  bottle do
    cellar :any_skip_relocation
    sha256 "06dfce7389b47808bdb3e3f72208e3bf294819da295b3d50392f99007d2092ee" => :high_sierra
    sha256 "81269990bae34fa36dec486d3a671edfe131d33d90d2d3650a747fc23639d622" => :sierra
    sha256 "f1d05d1888a83fd30dbafd6070456956ebe2e71f70b9808c6d59f7019ce0df8c" => :el_capitan
  end

  depends_on "node"

  def install
    system "npm", "install", *Language::Node.std_npm_install_args(libexec)
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    (testpath/"test.exp").write <<~EOS
      spawn #{bin}/firebase login:ci --no-localhost
      expect "Paste"
    EOS
    assert_match "authorization code", shell_output("expect -f test.exp")
  end
end

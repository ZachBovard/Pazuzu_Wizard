# Contributing

Beta 1 is a community collaboration. The wizard (`pazuzu_core`) and its manifests are open, and changes from outside
are welcome, the same way results from your own hardware are welcome in
[Hanbi_Hardware](https://github.com/ZachBovard/Hanbi_Hardware).

## What helps most

- **A fix** for something that went wrong on your firewall.
- **A firewall we have not seen:** an OPNsense version, a network layout or a port arrangement the wizard got wrong
  or refused.
- **Clearer words.** If a page left you unsure what would happen, say which page and what you expected.
- **A report without a fix.** An issue that says what you ran, what the page said and what you expected is a
  contribution too.

Results from a whole box or a part (what ran, what did not) belong in Hanbi_Hardware, not here.

## How to propose a change

1. **Small and clear** (a wrong word, a crash, a check that is too strict): open a pull request against `main`.
2. **Anything that changes what the wizard does to a firewall** (a rule, a service, a setting, an order of steps):
   open an issue first and say what you want and why. These are talked through before code, because one person's
   firewall is not everyone's.
3. **Say how you checked it.** The test suite is not in this repository yet. In the pull request, name the OPNsense
   version you ran the change on and what you saw, including what you could not try.
4. **Keep private details out.** No addresses, hardware addresses, serial numbers, Wi-Fi names, host names, keys or
   QR codes, in text, logs or screenshots.

## A security problem

If you find a way the wizard could weaken a firewall, leak a password or key, or be made to change a firewall without
its owner's approval, please do not open a public issue. Write to **security@hanbi.net** and say what you found and
how to see it. You get an answer, and credit when it is fixed if you want it.

## What every change keeps

- Nothing is changed on a firewall before the person has seen it and approved it.
- Every change is tested after it is made, and undone by itself if the test fails.
- The wizard does not start talking to a new place without the page saying so.
- Passwords and keys are never shown, logged or sent anywhere.

## What happens to your change

This repository is published from Hanbi's working copy, one commit for each build. A change that is accepted is taken
into that copy, goes through its tests, and appears here with the next build, with your name on it. A change that is
not taken gets a reason.

## The rules

- **Licence.** Contributions are made under the Apache License 2.0 (the LICENSE file), the same licence the code
  carries. By contributing you license your work under it.
- **Sign your commits.** Every commit needs a Developer Certificate of Origin sign-off, which says you wrote the
  change or otherwise have the right to submit it under the licence (DCO 1.1, developercertificate.org):

      Signed-off-by: Your Name <you@example.com>

  `git commit -s` adds the line for you. Pull requests with unsigned commits are asked to re-sign, nothing more.
- **The plugin and the manager are closed.** They are not in this repository and take no outside contributions. A
  few files that only work with them are left out too, so some choices do not show in a copy run from here.

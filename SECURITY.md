# Security

## Reporting a problem

If you find a way Pazuzu could weaken a firewall, leak a password or key, or be made to change a firewall without its
owner's approval, please do not open a public issue or pull request.

Write to **security@hanbi.net**. Say:

- what you found, and which build (the number on the wizard's first page, or the commit);
- how to see it happen, step by step;
- the OPNsense version, if it matters;
- whether you want to be named when it is fixed.

Leave out anything private: your addresses, hardware addresses, Wi-Fi names, host names, keys and passwords are not
needed to describe a fault. If a log or a screenshot holds them, cut them out first.

You get an answer. A fix goes out with the next build, and you are credited there if you want to be.

## What is covered

This repository: the wizard (`pazuzu_core`) and its manifests.

The Hanbi plugin, the manager and the apps are closed and are not here. A problem in one of them goes to the same
address.

A problem in OPNsense itself goes to the OPNsense project, not to Hanbi.

## What Pazuzu is meant to keep

A report is most useful when it shows one of these broken:

- Nothing is changed on a firewall before the person has seen it and approved it.
- Every change is tested after it is made, and undone by itself if the test fails.
- The wizard does not start talking to a new place without the page saying so.
- Passwords and keys are never shown, logged or sent anywhere.

## Supported builds

This is a beta. Only the newest build is fixed; please check that the problem is still there in it.

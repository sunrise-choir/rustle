# rustle

This is a cargo workspace for hacking on the various ssb crates.

It's also a (mostly useless) little program that exercises some of
the functionality of the crates.

## run

- `cargo run -- help`
- `cargo run -- help getfeed`

## join the fun

This project uses [git-subrepo](https://github.com/ingydotnet/git-subrepo) to make it easy
to make changes across several crates (which have their own repos) at the same time. You probably
don't need to install git-subrepo unless you need to push or pull changes to or from the subrepos.

We're still feeling out how well git-subrepo will work for us in practice; don't worry about breaking
stuff, we can figure out how to fix it together.

Normal development flow:

- make a fork of this repo, and/or `git clone`
- make some commits, changing files anywhere in the tree
- push your changes, and submit a pull request

## push changes to subrepos

- install [git-subrepo](https://github.com/ingydotnet/git-subrepo)
- `git subrepo status` to see the lay of the land
- do something like `git subrepo push ssb-legacy-msg`

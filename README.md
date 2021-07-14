CLI tool manage a redis instance, and a python object to manage a single redis key.

Don't use this:) You are most likely looking for: https://github.com/coleifer/walrus


```
$ rediskey --help
Usage: rediskey [OPTIONS] COMMAND [ARGS]...

Options:
  --ip TEXT
  --port INTEGER
  --ipython
  --progress
  --printn
  --debug
  --verbose
  --help          Show this message and exit.

Commands:
  add
  command-tree      show the command tree of your CLI
  delete-key
  delete-namespace  Clears a namespace :param ns: str, namespace i.e...
  list-key
  list-keys
  list-namespace
  list-namespaces
```

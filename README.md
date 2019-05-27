## Dev setup
Install the test packages
```
pip3 install --user -r test-requirements.txt
```
This will install pocha. Pocha comes with a binary for executing tests.
If you cannot find the command `pocha`, you may need to add local bin to your
PATH. Add the following to your `.bashrc`
```
PATH=$PATH:~/.local/bin/
```

Now you can run all tests with `pocha` or individual tests with `pocha <test>`.


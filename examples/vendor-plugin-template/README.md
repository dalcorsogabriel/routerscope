# routerscope vendor plugin template

A minimal, installable vendor plugin for a fictional "ExampleOS". Copy this folder, rename
the package and the `example_os` id, then implement `detect`, `parse_config` and friends.

```text
pyproject.toml                          # declares the routerscope.vendors entry point
src/routerscope_vendor_template/        # the plugin class (subclass BaseVendorPlugin)
```

Try it:

```console
$ pip install -e .
$ python -c "from routerscope.vendors import get; print(get('example_os'))"
```

The entry-point name (`example_os`) must equal the plugin class `id`. See
`docs/guides/add-a-vendor.md` in the routerscope repository for the full walkthrough.

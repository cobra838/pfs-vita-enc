# PS Vita PFS: Decryption and Re-encryption

English | [Русский](README.ru.md)

`pfs.py` processes PS Vita game files using **PFS metadata** (`sce_pfs/files.db`, `sce_pfs/unicv.db`) and **a license** (`sce_sys/package/work.bin`).

```bash
# Install the dependency:
python -m pip install -r requirements.txt
```

## Directory


```bash
# Decrypt encrypted_game into a new decrypted_game directory
python pfs.py decrypt encrypted_game decrypted_game

# Re-encrypt decrypted_game into a new rebuilt_game directory when decrypted_game contains its own PFS metadata and license
python pfs.py encrypt decrypted_game rebuilt_game

# If the metadata and license are stored elsewhere, provide their paths explicitly
python pfs.py encrypt decrypted_game rebuilt_game --sce-pfs saved/sce_pfs --license saved/work.bin
```

## Single file

The input file can be located **anywhere**. For a single file, provide both of these options:  
`--sce-pfs`: directory containing `files.db` and `unicv.db`.  
`--license`: path to `work.bin` or a `.rif` file.  
`--path` selects the relative file path recorded in `files.db`. It usually matches the file's path in the extracted files. It is neither the input path nor the output path.

```bash
# Decrypt encrypted_icon.png into icon.png, using the sysdata/icon.png entry in files.db
python pfs.py decrypt encrypted_icon.png icon.png --sce-pfs saved/sce_pfs --license saved/work.bin --path sysdata/icon.png
```

To re-encrypt a single file, use the same metadata and license:

```bash
python pfs.py encrypt icon.png encrypted_icon_new.png --sce-pfs saved/sce_pfs --license saved/work.bin --path sysdata/icon.png
```

Here, `encrypt` creates `encrypted_icon_new.png`, the encrypted version of the input `icon.png`. It also creates `encrypted_icon_new.png.unicv.db`, a complete `unicv.db` with updated signatures for that file.  
In single-file mode, the script compares the input size with the value in the supplied `files.db`. If you supply the original `sce_pfs`, single-file mode cannot encrypt a file whose size has changed; use directory mode for that case.  
For another decryption, the script automatically uses a neighboring `.unicv.db` file if one exists. Use `--unicv` to specify a different path.

## Behavior

If a filename is unique among the recorded files, you can omit `--path`.  
If several files are named `icon.png`, select the intended entry with a path such as `--path sysdata/icon.png`.

In directory mode, `--sce-pfs` and `--license` are optional: the script looks for `sce_pfs` and `sce_sys\package\work.bin` in the input directory. Decryption copies them to the output, so the decrypted directory can later be re-encrypted without the original encrypted directory. If the metadata or license is stored elsewhere, supply its path with `--sce-pfs` and `--license`.

`sce_pfs` contains metadata, not game file contents. When processing a directory, the script processes files listed in `files.db`: it applies the requested operation to files marked as encrypted and copies the others unchanged. It reports an error if a single input file has no entry in `files.db`. When encrypting a directory, it updates existing file sizes in the output `files.db`, sector counts and signatures in the output `unicv.db`, and entries in `pflist` if that file exists. The input directories are not modified; the output directory must not already exist.

## Re-encryption limitations

All files listed in the original PFS must remain at the same relative paths.  
Adding or removing files is not supported.  
Changing file sizes is supported when encrypting a **directory**. When encrypting a single file with the original `sce_pfs`, its size cannot be changed.  
Only game PFS with `unicv.db`, `image_spec=1`, and `key_id=0` is supported. Other variants result in an error.

## Sources

The algorithm and format were checked against
[Vita3K/psvpfsparser](https://github.com/Vita3K/psvpfsparser).

+++
date = '2024-11-13T10:22:25-05:00'
draft = true
title = 'Unpatched Remote Code Execution in Gogs'
+++

The [Gogs](https://gogs.io/) self-hosted Git service is vulnerable to symbolic link path traversal that enables remote code execution ([CVE-2024-44625](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-44625)). The latest version at the time of writing (0.13.0) is affected. This vulnerability is exploitable against a default install, with the only attacker requirement being access to an account that can push to a repository and edit that repository's files from the web interface.

Per Gogs' [`SECURITY.md`](https://github.com/gogs/gogs/blob/2541348408e120e9acd4ff7fb6419e3a00233c67/SECURITY.md), I reported this issue to the maintainers as a GitHub advisory on August 10, 2024. Though I followed up multiple times, my report was never acknowledged and remains unaddressed at the time of writing. My experience here was not an anomaly; there is currently an [open issue](https://github.com/gogs/gogs/issues/7777) tracking several other high and critical vulnerabilities left unpatched due to a lack of response from the Gogs developers.

As the 90-day disclosure deadline I gave in my report has now passed, I am publishing the full technical details of CVE-2024-44625, as well as a proof-of-concept exploit. I advise anyone running Gogs to close off access to the public and untrusted users, disable user registration, set strong passwords and enable 2FA for existing accounts, and migrate to [Gitea](https://about.gitea.com/), which is an actively maintained fork of Gogs not affected by this vulnerability.
## The vulnerability

Gogs' web editor allows the user to modify and rename repository files directly from the web interface. When the user submits their edits, the frontend issues a POST request to the `/:username/:reponame/_edit/:branch/:filepath` endpoint. The request is handled by the [`editFilePost`](https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/route/repo/editor.go#L122) function, which validates/sanitizes the request parameters and eventually calls the [`UpdateRepoFile`](https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/database/repo_editor.go#L121) function. `UpdateRepoFile` then performs the requested changes as a series of direct filesystem operations on a clone of the repository and commits them.

Below is a snippet from `UpdateRepoFile` that shows the core logic for modifying and renaming a file ([`internal/database/repo_editor.go#L159-L196`](https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/database/repo_editor.go#L159-L196)).

```go {linenos=table,hl_lines=[22],linenostart=159}
oldFilePath := path.Join(localPath, opts.OldTreeName)
filePath := path.Join(localPath, opts.NewTreeName)
if err = os.MkdirAll(path.Dir(filePath), os.ModePerm); err != nil {
    return err
}

// If it's meant to be a new file, make sure it doesn't exist.
if opts.IsNewFile {
    if com.IsExist(filePath) {
        return ErrRepoFileAlreadyExist{filePath}
    }
}

// Ignore move step if it's a new file under a directory.
// Otherwise, move the file when name changed.
if osutil.IsFile(oldFilePath) && opts.OldTreeName != opts.NewTreeName {
    if err = git.Move(localPath, opts.OldTreeName, opts.NewTreeName); err != nil {
        return fmt.Errorf("git mv %q %q: %v", opts.OldTreeName, opts.NewTreeName, err)
    }
}

if err = os.WriteFile(filePath, []byte(opts.Content), 0600); err != nil {
    return fmt.Errorf("write file: %v", err)
}

if err = git.Add(localPath, git.AddOptions{All: true}); err != nil {
    return fmt.Errorf("git add --all: %v", err)
}

err = git.CreateCommit(
    localPath,
    &git.Signature{
        Name:  doer.DisplayName(),
        Email: doer.Email,
        When:  time.Now(),
    },
    opts.Message,
)
```

Because the code writes to client-controlled file paths (via a call to `os.WriteFile`, highlighted above), care must be taken to prevent modifications to files outside of the clone directory. The classic example of this is path traversal, in which we might submit a path of `../../../foo` to write to a file other than the intended destination. Part of the aforementioned parameter sanitization in `editFilePost` [prevents](https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/route/repo/editor.go#L138) this basic kind of traversal.

However, there is another type of vulnerability that can have the same effect as traditional path traversal: symbolic link following. If we added a symlink to `/tmp/foo` to a repository, pushed it to Gogs, and modified the link's contents using the web editor, we would have actually modified the contents of `/tmp/foo`. Note that this potential exists because `os.WriteFile` opens the file [without specifying](https://cs.opensource.google/go/go/+/refs/tags/go1.23.3:src/os/file.go;l=831) the `O_NOFOLLOW` flag, causing `UpdateRepoFile` to follow any symlinks present in the repository.

The developers anticipated this possibility and added a guard against it in `editFilePost`, shown below ([internal/route/repo/editor.go#L175-L198](https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/route/repo/editor.go#L175-L198)).

```go {linenos=table,hl_lines=["21-24"],linenostart=175}
var newTreePath string
for index, part := range treeNames {
    newTreePath = path.Join(newTreePath, part)
    entry, err := c.Repo.Commit.TreeEntry(newTreePath)
    if err != nil {
        if gitutil.IsErrRevisionNotExist(err) {
            // Means there is no item with that name, so we're good
            break
        }

        c.Error(err, "get tree entry")
        return
    }
    if index != len(treeNames)-1 {
        if !entry.IsTree() {
            c.FormErr("TreePath")
            c.RenderWithErr(c.Tr("repo.editor.directory_is_a_file", part), tmplEditorEdit, &f)
            return
        }
    } else {
        if entry.IsSymlink() {
            c.FormErr("TreePath")
            c.RenderWithErr(c.Tr("repo.editor.file_is_a_symlink", part), tmplEditorEdit, &f)
            return
        // ...
```

Here, `treeNames` is a slice containing the components of the _new_ path (in case it is being renamed) of the file being edited. The code iterates over these components, appending the current component to `newTreePath` and checking the Git tree entry at the value of `newTreePath`. If the entry is a symlink, the request is rejected and an error message is displayed to the user (highlighted above). For example, given the path `foo/bar/baz`, if any one of `foo`, `foo/bar`, or `foo/bar/baz` is a symlink, `editFilePost` rejects the request.

However, notice the opportunity on lines 179-182 to break from the loop before the symlink check is performed. If `newTreePath` is a path that is not already part of the repository (that is, a nonexistent file), the loop ends early, skipping over the symlink check. The consequence is that editing a symlink's contents while _simultaneously_ moving it to a path that does not already exist allows us to modify arbitrary files on the system.

With this primitive in hand, we can achieve code execution by taking advantage of [server-side Git hooks](https://git-scm.com/book/ms/v2/Customizing-Git-Git-Hooks#_server_side_hooks). These are scripts that live in the repository's `hooks` directory on the server, executed at various points before and after a push to the server. We can create a symlink to one of these hook files, such as `pre-receive`, and overwrite its contents with a command of our choice. The hook and our command will then automatically execute without any extra work on our part when Gogs updates the repository with the new symlink contents.

## Exploit
A proof-of-concept exploit script can be found [here](https://github.com/Fysac/CVE-2024-44625/blob/main/poc.py).

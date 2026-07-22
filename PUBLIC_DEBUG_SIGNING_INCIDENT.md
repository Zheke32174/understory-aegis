
# Public debug-signing incident

The same shared debug private key was committed to the public Understory Android
repositories and used as a runtime trust pin. That key is now revoked for
authorship, self-tamper, sibling identity, and capability authority.

This containment branch removes the key from the current tree, stops automatic
debug APK publication, preserves ordinary local debug builds without treating
them as trusted, disables trusted cross-app capability discovery in debug
variants, and retains the externally held release certificate as the only suite
identity.

Existing Release assets, tags, workflow artifacts, and Git history were not
changed by this draft. Their disposition requires explicit steward action.
Coordination: `Zheke32174/understory-common#3`.

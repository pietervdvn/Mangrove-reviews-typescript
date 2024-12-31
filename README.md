# This repository moved

Find us at https://source.mapcomplete.org/MapComplete/Mangrove-reviews-typescript

# Mangrove-reviews-typescript



This is a port of [mangrove-reviews](https://www.npmjs.com/package/mangrove-reviews), but which uses [jose](https://www.npmjs.com/package/jose) instead of [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken).
The latter has a dependency which uses `Stream`, which `vite` cannot handle.

Another benefit is that this one has better typing* and should thus be more ergonomic to use.

(*): typing is incomplete and only includes the very basic usecase of downloading and uploading reviews - the bare minimum of what I needed for MapComplete.
However, I'll gladly merge pull requests which add more types.


'use strict';
// Minimal in-memory Firestore: only the API surface src/ uses (collection/doc/get/set/update/create/delete,
// getAll, batch, runTransaction).  Transactions are serialised, so it models correctness of the *logic*,
// not Firestore's contention/retry behaviour.
const clone = o => (o === undefined ? undefined : JSON.parse(JSON.stringify(o)));

function makeFakeDb() {
    const store = new Map();                       // "col/id" -> data
    let chain = Promise.resolve();
    const snap = (id, path) => ({ id, exists: store.has(path), data: () => clone(store.get(path)) });
    const err = (code, message) => Object.assign(new Error(message), { code });
    const write = {
        set: (p, d) => store.set(p, clone(d)),
        create: (p, d) => { if (store.has(p)) throw err(6, 'ALREADY_EXISTS'); store.set(p, clone(d)); },
        update: (p, d) => { if (!store.has(p)) throw err(5, 'NOT_FOUND'); store.set(p, { ...store.get(p), ...clone(d) }); },
        delete: p => store.delete(p),
    };
    const db = {
        _store: store,
        collection: col => ({
            doc: id => {
                const path = `${col}/${id}`;
                return { id, path, get: async () => snap(id, path),
                    set: async d => write.set(path, d), create: async d => write.create(path, d),
                    update: async d => write.update(path, d), delete: async () => write.delete(path) };
            },
            get: async () => {
                const docs = [...store.keys()].filter(k => k.startsWith(col + '/')).sort()
                    .map(k => snap(k.slice(col.length + 1), k));
                return { docs, size: docs.length, empty: !docs.length };
            },
        }),
        getAll: async (...refs) => { if (!refs.length) throw new Error('getAll needs refs'); return refs.map(r => snap(r.id, r.path)); },
        batch: () => {
            const ops = [];
            return {
                set: (r, d) => ops.push(() => write.set(r.path, d)), update: (r, d) => ops.push(() => write.update(r.path, d)),
                delete: r => ops.push(() => write.delete(r.path)), create: (r, d) => ops.push(() => write.create(r.path, d)),
                commit: async () => { if (ops.length > 500) throw new Error('batch > 500'); ops.forEach(o => o()); },
            };
        },
        runTransaction: fn => (chain = chain.catch(() => {}).then(async () => {
            const pending = []; let wrote = false;
            const tx = {
                get: async r => { if (wrote) throw new Error('reads must precede writes'); return snap(r.id, r.path); },
                set: (r, d) => { wrote = true; pending.push(() => write.set(r.path, d)); },
                update: (r, d) => { wrote = true; pending.push(() => write.update(r.path, d)); },
                delete: r => { wrote = true; pending.push(() => write.delete(r.path)); },
            };
            const out = await fn(tx);
            pending.forEach(p => p());
            return out;
        })),
    };
    return db;
}
module.exports = { makeFakeDb };

// Runs once, when MongoDB starts on an empty volume (docker-entrypoint-initdb.d): Studio's own
// database user, limited to Studio's database. The root user from MONGO_INITDB_ROOT_* stays
// for administration only. Both passwords come from /opt/mivais/mongo.env on the VM.
db.getSiblingDB("mivais_studio").createUser({
  user: "studio",
  pwd: process.env.STUDIO_DB_PASSWORD,
  roles: [{ role: "readWrite", db: "mivais_studio" }],
});

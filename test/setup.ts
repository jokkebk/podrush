if (process.env.NODE_ENV === "test" && !process.env.PODRUSH_DB_PATH && !process.env.DB_PATH) {
  process.env.PODRUSH_DB_PATH = "db.test.sqlite";
}

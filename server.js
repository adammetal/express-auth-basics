const app = require("./_app");

const port = process.env?.PORT ?? 8080;

app.listen(port, () => {
  console.log(`App is running on ${port}`);
});

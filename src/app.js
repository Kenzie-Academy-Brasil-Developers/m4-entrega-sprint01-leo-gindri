import express from "express";

const app = express();

app.get("/", (req, resp) => {
  return resp.send(
    "Saudade do next, acho que vou meter o louco e fazer algum site ;D"
  );
});

const PORT = 3000;

app.listen(PORT, () => {
  return "App funcioanando corretamente";
});

export default app;

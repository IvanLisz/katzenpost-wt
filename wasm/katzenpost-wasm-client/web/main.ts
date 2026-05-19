import { mountKatzenpostWtMvp } from "./index";

const root = document.getElementById("app");
if (!root) {
  throw new Error("missing #app");
}

mountKatzenpostWtMvp(root);

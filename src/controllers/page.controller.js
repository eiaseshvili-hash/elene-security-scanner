export function renderHomePage(req, res) {
  return res.render("pages/home", {
    title: "Elene Project",
    description: "Domain, DNS, SSL and web security scanner"
  });
}
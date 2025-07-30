import React from "react";

function Footer() {
  return (
    <footer className="footer items-center p-4 bg-neutral text-neutral-content">
      <div className="items-center grid-flow-col">
        <p>PhishGuard - Advanced Phishing Detection</p>
      </div>
      <div className="grid-flow-col gap-4 md:place-self-center md:justify-self-end">
        <p>© {new Date().getFullYear()} All Rights Reserved</p>
      </div>
    </footer>
  );
}

export default Footer;

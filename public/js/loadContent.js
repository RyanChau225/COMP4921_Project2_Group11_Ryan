const links = [
  {
      id: 1,
      url: "https://example1.com",
      shortUrl: "https://exmpl1.com",
      hits: 10,
      active: true,
      created: "01/01/2023",
      lastHit: "05/01/2023"
  },
  {
      id: 2,
      url: "https://example2.com",
      shortUrl: "https://exmpl2.com",
      hits: 5,
      active: false,
      created: "02/01/2023",
      lastHit: "03/01/2023"
  },
  {
      id: 3,
      url: "https://example3.com",
      shortUrl: "https://exmpl3.com",
      hits: 20,
      active: true,
      created: "03/01/2023",
      lastHit: "04/01/2023"
  },
  // ... your existing links
];

// Generating 12 additional dummy data
for (let i = 4; i <= 15; i++) {
  links.push({
      id: i,
      url: `https://example${i}.com`,
      shortUrl: `https://exmpl${i}.com`,
      hits: Math.floor(Math.random() * 50),  // random number of hits between 0 and 50
      active: Math.random() < 0.5,  // random boolean for active status
      created: `0${i % 5 + 1}/01/2023`,
      lastHit: `0${(i + 2) % 5 + 1}/01/2023`
  });
}


document.addEventListener("DOMContentLoaded", function() {
  // Load header
  fetch('../template/header.html')
      .then(response => response.text())
      .then(content => {
          document.getElementById('header').innerHTML = content;
      });

  // Load footer
  fetch('../template/footer.html')
      .then(response => response.text())
      .then(content => {
          document.getElementById('footer').innerHTML = content;
      });

  // Load footer
  fetch('../template/links.html')
      .then(response => response.text())
      .then(content => {
          document.getElementById('links').innerHTML = content;
      });



    setupInteractiveElements();
});
function setupInteractiveElements() {
  populateTable();

  const searchBox = document.getElementById("searchBox");
  searchBox.addEventListener("input", searchFunction);

  document.getElementById('btnAddLink').addEventListener('click', function() {
      const newLink = prompt("Enter the new link:");
      if (newLink) {
          links.push(newLink);
          populateTable();
      }
  });

  // Similarly, for images and text:
  // Assuming you just want to add URLs for images and plain text for text
  document.getElementById('btnAddImage').addEventListener('click', function() {
      const newImageLink = prompt("Enter the image link:");
      if (newImageLink) {
          links.push(newImageLink);
          populateTable();
      }
  });

  document.getElementById('btnAddText').addEventListener('click', function() {
      const newText = prompt("Enter the text:");
      if (newText) {
          links.push(newText);
          populateTable();
      }
  });
}

document.addEventListener("mousemove", function(e) {
  const header = document.querySelector(".navbar");
  // If the mouse is within 50 pixels from the top of the viewport, show the header
  if (e.clientY <= 50) {
      header.style.opacity = "1";
  } else {
      header.style.opacity = "0";
  }
});


function populateTable() {
  const tableBody = document.querySelector("#linksTable tbody");
  tableBody.innerHTML = '';  // Clear the existing rows

  links.forEach(link => {
      const row = tableBody.insertRow();
      
      let cell = row.insertCell(0);
      cell.textContent = link.id;

      cell = row.insertCell(1);
      const anchor = document.createElement("a");
      anchor.href = link.url;
      anchor.textContent = link.url;
      cell.appendChild(anchor);

      cell = row.insertCell(2);
      const shortAnchor = document.createElement("a");
      shortAnchor.href = link.shortUrl;
      shortAnchor.textContent = link.shortUrl;
      cell.appendChild(shortAnchor);

      cell = row.insertCell(3);
      cell.textContent = link.hits;

      cell = row.insertCell(4);
      cell.textContent = link.active ? "Yes" : "No";

      cell = row.insertCell(5);
      cell.textContent = link.created;

      cell = row.insertCell(6);
      cell.textContent = link.lastHit;
  });
}


function searchFunction() {
  const query = this.value.toLowerCase();
  const rows = document.querySelectorAll("#linksTable tbody tr");
  rows.forEach(row => {
      const link = row.querySelector("a").href.toLowerCase();
      if (link.includes(query)) {
          row.style.display = "";
      } else {
          row.style.display = "none";
      }
  });
}

document.addEventListener('DOMContentLoaded', function () {
  // Add an event listener for page load
  window.addEventListener('pageshow', function (event) {
      var form = document.getElementById('signup-form');
      if (form) {
          // Reset the form fields
          form.reset();
      }
  });
});

document.addEventListener('DOMContentLoaded', () => {
// Get the file input and file name elements
const fileInput = document.getElementById('profile_pic');
const fileInputName = document.querySelector('.file-name');

// Listen for changes on the file input
fileInput.addEventListener('change', (event) => {
// Get the file name
const fileName = event.target.files.length > 0 ? event.target.files[0].name : 'No file uploaded';

// Update the file-name element
fileInputName.textContent = fileName;
});
});
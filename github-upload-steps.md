# Upload Your Repository to GitHub

## Step 1: Create a new repository on GitHub
1. Go to [GitHub](https://github.com/) and sign in to your account
2. Click on the "+" icon in the top right corner and select "New repository"
3. Enter a repository name (e.g., "user-service")
4. Add a description (optional)
5. Keep it as a Public repository (or choose Private if you prefer)
6. **Important**: Do NOT initialize the repository with a README, .gitignore, or license file
7. Click "Create repository"

## Step 2: Run these commands in your terminal

After creating the repository on GitHub, you'll see a page with instructions. Copy the URL of your new repository (it will look like `https://github.com/YOUR_USERNAME/REPO_NAME.git`).

Then run these commands in your terminal, replacing the URL with your actual repository URL:

```
git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git
git branch -M main
git push -u origin main
```

## Step 3: Enter your GitHub credentials
When prompted, enter your GitHub username and password or personal access token.

## Step 4: Verify the upload
1. Refresh your GitHub repository page
2. You should see all your files uploaded, including the MIT License

## Important Note
Before pushing, make sure to edit the LICENSE file to replace "[Please replace with your actual name]" with your actual name. 
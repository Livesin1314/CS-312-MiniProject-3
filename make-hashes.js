//importing the bcrypt so that it can get hash passwords
const bcrypt = require("bcrypt");
//creating the asynchronus function to generate password hashess
async function main(){
   //generate a hash for each password and storign the password in an array
   const passwords = [
      "AliceBLog123!",
      "BobBlog123!",
      "CharlieBlog123!"
   ];
   //A loop that passes through the array
   for (const password of passwords){
      //have the passwords become has by using the bcrpt
      const hash = await bcrypt.hash(password, 10);
      //printing the original password and the hash
      console.log(password + " => " + hash);
   }
}
//Have the main function start generating the password hashes
main();
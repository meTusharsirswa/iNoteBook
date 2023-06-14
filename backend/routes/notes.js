const express =require('express');
const router =express.Router();
var fetchuser =require('../middlleware/fetchuser')
const Note = require('../models/Note')
const { body, validationResult } = require('express-validator');



//  ROUTE 1 : Get All the Notes using :GET "/api/notes/getuser". Login required 
router.get('/fetchallnotes',fetchuser,async (req,res)=>{
    try {
        const notes = await Note.find({user: req.user.id});
    res.json(notes)
        
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal server Error")
    }
})

//  ROUTE 2 : Get All new Notes using :post "/api/notes/addnote". Login required 
router.post('/addnote',fetchuser,[
    body('title','Enter a valid title').isLength({ min: 3 }),
    body('description','Description must be atleast 5 characters').isLength({ min:5}),           
], async (req,res)=>{

    try {     
    const {title,description,tag}= req.body;
        // if there are errors, return bad request and the errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ errors: errors.array() });
        }  
        const note =new Note({
            title,description,tag,user: req.user.id
        })
        const savedNote = await note.save()
        
    res.json(savedNote)
} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server Error")
}
})

//  ROUTE 3 : Update an existing  Note using :PUT "/api/notes/updatenote". Login required 
router.put('/updatenote/:id', fetchuser,async (req,res) =>{
    const {title,description,tag} = req.body;

    try {  
    // Create a newNote Object
    const newNote ={};
    if(title){newNote.title = title};
    if(description){newNote.description =description};
    if(tag){newNote.tag =tag};

    // Find the note to be updated and udate it 
    let note =await Note.findById(req.params.id);
    if(!note){return res.status(404).send("Not Found")}

    if(note.user.toString() !== req.user.id){
        return res.status(401).send("Not Allowed");
    }

    note = await Note.findByIdAndUpdate(req.params.id, {$set: newNote}, {new:true})
    res.json({note});

} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server Error")
}
})


//  ROUTE 4 : Delete an existing Note using :DELETE "/api/notes/deletenote". Login required 
router.delete('/deletenote/:id', fetchuser,async (req,res) =>{
  
    try {  
    // Find the note to be deleted and delete it 
    let note =await Note.findById(req.params.id);
    if(!note){return res.status(404).send("Not Found")}

    // Allow deletion only if user owns this Note
    if(note.user.toString() !== req.user.id){
        return res.status(401).send("Not Allowed");
    }

    note = await Note.findByIdAndDelete(req.params.id)
    res.json({ " Success": "Note has been deleted", note : note});
} catch (error) {
    console.log(error.message);
    res.status(500).send("Internal server Error")
}
})







module.exports =router
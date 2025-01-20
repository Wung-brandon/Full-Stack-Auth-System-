import { useState } from 'react'

const VerifyEmail = () => {
  return (
    <div className='' style={{width:"100%"}}>
      <div className='container-fluid card shadow'>
        <form action=''>
          <div className='form-group'>
            <label htmlFor='' className="form-label">Enter your Otp code:</label>
            <input type="text" className=" form-control" name="otp"/>
          </div>
          <div className="d-grid">
              <button type="submit" className="btn btn-primary mt-4">Send</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default VerifyEmail